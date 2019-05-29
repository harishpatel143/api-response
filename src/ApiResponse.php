<?php

/**
 * Copyright 2018, Multidots Solutions Pvt Ltd (https://www.multidots.com).
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @copyright Copyright 2018, Multidots Solutions Pvt Ltd (https://www.multidots.com)
 * @license MIT License (http://www.opensource.org/licenses/mit-license.php)
 */

namespace App\Controller;

use Cake\Core\Configure;
use Cake\Mailer\Email;
use Cake\ORM\TableRegistry;
use Cake\Routing\Router;
use Google_Client;
use Google_Service_Oauth2;

/**
 * Account controller.
 *
 * This controller file used to handle basic login related functionality
 */
class ApiResponse extends AppController
{
    /**
     * Controller name.
     *
     * @var string
     */
    public $name = 'Account';

    /**
     * Active side-bar menu.
     *
     * @var string
     */
    public $activeSidebarMenu = 'dashboard';

    /**
     * Initialization hook method.
     *
     * @return void
     */
    public function initialize()
    {
        parent::initialize();
        $this->loadComponent('Csrf');
    }

    /**
     * Login method.
     *
     * @return \Cake\Http\Response|void
     */
    public function login()
    {
        $recentUrl = $this->request->session()->read(Configure::read('SYSTEM.sessionRecentUrlKeyName'));
        if ($this->request->is('post')) {
            if (!empty($this->request->data['User'])) {
                $users = TableRegistry::get('Users');
                $entity = $users->newEntity($this->request->data['User'], ['validate' => 'Login']);
                if (!$entity->errors()) {
                    $user = $users->find()->contain(['Roles' => ['fields' => ['id', 'name']]])
                                    ->where(['Users.email' => $this->request->data['User']['email'], 'Users.password' => md5($this->request->data['User']['password']), 'Users.status' => Configure::read('Status.active')])->first();
                    if (!empty($user)) {
                        $remember = !(empty($this->request->data['User']['remember'])) ? true : false;
                        if ($user->is_first_time_login) {
                            $this->Flash->set(__('You have successfuly logged in. Please change your password first.'), ['element' => 'success']);
                            $user->is_first_time_login = 0;
                            $user = $users->save($user);
                            $this->AccessControl->setUser($user->toArray(), $remember);

                            return $this->redirect(['_name' => 'account-edit-profile', 'tab_1_3']);
                        } else {
                            $this->Flash->set(__('You have successfuly logged in.'), ['element' => 'success']);
                        }
                        $this->AccessControl->setUser($user->toArray(), $remember);

                        $reqData = $this->request->getData();
                        if (!empty($reqData['hash_tags']) && !empty($recentUrl)) {
                            $recentUrl = $recentUrl.$reqData['hash_tags'];
                        }
                        $recentUrl = !empty($recentUrl) ? $recentUrl : '/';

                        return $this->redirect($recentUrl);
                    } else {
                        $this->Flash->set(__('Invalid email or password. Please try again.'), ['element' => 'error']);
                    }
                } else {
                    $this->Flash->set(__('Email or password can not be empty. Please try again.'), ['element' => 'error']);
                }
            }
        }
        $this->set('title', [__('Login')]);
        $this->viewBuilder()->layout('login');
    }

    /**
     * Gmail login.
     *
     * @return \Cake\Http\Response|void
     */
    public function googlelogin()
    {
        $client = new Google_Client();
        $client->setClientId(Configure::read('Google.googleClientID'));
        $client->setClientSecret(Configure::read('Google.googleClientSecret'));
        $client->setRedirectUri(Configure::read('Google.googleRedirectUrl'));
        $client->setScopes([
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ]);
        $url = $client->createAuthUrl();
        $this->redirect($url);
    }

    /**
     * Gmail auth redirect action.
     *
     * @return \Cake\Http\Response|void
     */
    public function confirmlogin()
    {
        $client = new Google_Client();
        $client->setClientId(Configure::read('Google.googleClientID'));
        $client->setClientSecret(Configure::read('Google.googleClientSecret'));
        $client->setRedirectUri(Configure::read('Google.googleRedirectUrl'));
        $client->setScopes([
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email',
        ]);
        $client->setAccessType('offline');
        $client->setApprovalPrompt('auto');
        $usersTable = TableRegistry::get('Users');
        if (isset($this->request->query['code'])) {
            $client->authenticate($this->request->query['code']);
            $this->request->Session()->write('access_token', $client->getAccessToken());
        }

        if ($this->request->Session()->check('access_token') && ($this->request->Session()->read('access_token'))) {
            $client->setAccessToken($this->request->Session()->read('access_token'));
        }
        if ($client->getAccessToken()) {
            $this->request->Session()->write('access_token', $client->getAccessToken());
            $oauth2 = new Google_Service_Oauth2($client);
            $user = $oauth2->userinfo->get();

            try {
                if (!empty($user)) {
                    $result = $usersTable->find('all')
                        ->where(['email' => $user['email']])
                        ->first();

                    if (!empty($result) && $result['status'] == Configure::read('Status.active')) {
                        if (!empty($result)) {
                            $result->socialId = $user['id'];
                            $usersTable->save($result);
                            $this->AccessControl->setUser($result->toArray(), false);
                            $this->Flash->set(__('You have successfuly logged in.'), ['element' => 'success']);

                            return $this->redirect(['_name' => 'dashboard']);
                        } else {
                            $data = [];
                            $data['email'] = $user['email'];
                            $data['first_name'] = $user['givenName'];
                            $data['last_name'] = $user['familyName'];
                            $data['socialId'] = $user['id'];
                            $data['role_id'] = Configure::read('Role.loginWithGmailUserRole');
                            //$data matches my Users table
                            $entity = $usersTable->newEntity($data);
                            if ($usersTable->save($entity)) {
                                $data['id'] = $entity->id;
                                $this->AccessControl->setUser($data, false);
                                $this->Flash->set(__('You have successfuly logged in.'), ['element' => 'success']);

                                return $this->redirect(['_name' => 'dashboard']);
                            } else {
                                $this->request->session()->destroy();
                                $this->Flash->error(__('Invalid login.'));

                                return $this->redirect(['_name' => 'account-login']);
                            }
                        }
                    } elseif (!empty($result) && $result['status'] != Configure::read('Status.active')) {
                        $this->request->session()->destroy();
                        $this->Flash->error(__('Your account is inactive.'));

                        return $this->redirect(['_name' => 'account-login']);
                    } else {
                        $this->request->session()->destroy();
                        $this->Flash->error(__('Looks like, You are not registered with MD-PMS.'));

                        return $this->redirect(['_name' => 'account-login']);
                    }
                } else {
                    $this->request->session()->destroy();
                    $this->Flash->error(__('Gmail infos not found.'));

                    return $this->redirect(['_name' => 'account-login']);
                }
            } catch (\Exception $e) {
                $this->Flash->error(__('Gmail error.'));

                return $this->redirect(['_name' => 'account-login']);
            }
        }
    }

    /**
     * View Profile method.
     *
     * @param type $id user id
     *
     * @return \Cake\Http\Response|void
     */
    public function profile($id = null)
    {
        $users = TableRegistry::get('Users');
        if (empty($id)) {
            $sessionData = $this->AccessControl->user();
            $userDetails = $users->find()
                            ->contain(['Roles'  => ['fields' => ['id', 'name']],
                                'Departments'   => ['fields' => ['id', 'name'], 'joinType' => 'Left'],
                                'ProjectsUsers' => ['fields' => ['id', 'user_id']],
                                'TasksUsers'    => ['fields' => ['id', 'user_id']],
                                'Designations'  => ['fields' => ['id', 'name']],
                            ])
                            ->where(['Users.id' => $sessionData['id']])->first();
        } else {
            $userDetails = $users->find()
                            ->contain(['Roles'  => ['fields' => ['id', 'name']],
                                'Departments'   => ['fields' => ['id', 'name'], 'joinType' => 'Left'],
                                'ProjectsUsers' => ['fields' => ['id', 'user_id']],
                                'TasksUsers'    => ['fields' => ['id', 'user_id']],
                                'Designations'  => ['fields' => ['id', 'name']],
                            ])
                            ->where(['Users.id' => $id, 'Users.status' => Configure::read('Status.active')])->first();
        }

        $this->loadModel('Projects');
        $projectCount = $this->Projects->getUsersProjectsCount($userDetails['role_id'], $userDetails['id']);

        $this->loadModel('TasksUsers');
        $taskCount = $this->TasksUsers->getUsersTasksCount($userDetails['role_id'], $userDetails['id']);
        if (empty($userDetails)) {
            $this->Flash->set(__('User does not exist.'), ['element' => 'error']);

            return $this->redirect(['_name' => 'dashboard']);
        }
        $editProfileActive = 1;
        $this->set(compact('editProfileActive'));
        $this->set(compact('userDetails', 'id', 'projectCount', 'taskCount'));
        $this->set('title', [__('User Profile')]);
        $this->pageNavigation = [
            'view' => [
                'title'  => h('User Profile'),
                'active' => true,
            ],
        ];
    }

    /**
     * Edit Profile method.
     *
     * @param type $id user id
     *
     * @return \Cake\Http\Response|void
     */
    public function editProfile($id = null)
    {
        $timezones = timezone_identifiers_list();
        $timeZoneList = array_combine($timezones, array_values($timezones));
        $sessionData = $this->AccessControl->user();
        $users = TableRegistry::get('Users');
        $userDetails = $users->get($sessionData['id'], ['contain' => ['Roles' => ['fields' => ['id', 'name']], 'Departments' => ['fields' => ['id', 'name'], 'joinType' => 'Left'], 'ProjectsUsers' => ['fields' => ['id', 'user_id']], 'TasksUsers' => ['fields' => ['id', 'user_id']]]], ['conditions' => ['status' => Configure::read('Status.active')]]);
        $designationsList = $users->Designations->find('list')->where(['status <>' => Configure::read('Status.deleted')])->order(['name' => 'ASC'])->toArray();
        if ($this->request->is(['put', 'post', 'patch'])) {
            // Update Basic Details
            $user = $users->patchEntity($userDetails, $this->request->data, ['validate' => 'editProfile']);
            if (!empty($user->join_date)) {
                $joinDate = str_replace('/', '-', $user->join_date);
                $user->join_date = trim($this->Common->formatDate($joinDate, 'Y-m-d'));
            }
            if (empty($user->errors())) {
                $users->save($user);
                $this->Flash->success(__('Profile has been updated sucessfully.'));
                if ($user->id == $sessionData['id']) {
                    $this->AccessControl->setUser($user->toArray(), false);

                    return $this->redirect(['_name' => 'account-profile']);
                }
            }

            // Update Avatar
            if (!empty($this->request->data['avatar']) || (isset($this->request->data['delete_image']) && $this->request->data['delete_image'] == 1)) {
                $user = $users->get($sessionData['id'], ['conditions' => ['status' => Configure::read('Status.active')]]);
                $oldProfile = $user->avatar;
                if (!empty($this->request->data['avatar']['tmp_name'])) {
                    //Upload image
                    $this->MDImage->setupVars(['uploadBasePath' => Configure::read('Media.profileImagePath')]);
                    $uploadedImage = $this->MDImage->uploadImage($this->request->data['avatar']);
                }
                if ($this->request->data['delete_image'] == 0) {
                    $user->avatar = !empty($uploadedImage['imageName']) ? basename($uploadedImage['imageName']) : $oldProfile;
                } else {
                    $user->avatar = '';
                }
                if ($users->save($user)) {
                    if (!empty($oldProfile) && ($this->request->data['delete_image'] == 1) && file_exists(Configure::read('Media.profileImagePath').$oldProfile)) {
                        unlink(Configure::read('Media.profileImagePath').$oldProfile); //Remove Old Image
                    }
                    if ($user->id == $sessionData['id']) {
                        $this->AccessControl->setUser($user->toArray(), false);
                    }
                    $this->Flash->success(__('Avatar has been updated sucessfully.'));
                }
            }

            // Change Password
            if (!empty($this->request->data['password'])) {
                $user = $users->get($sessionData['id'], ['conditions' => ['status' => Configure::read('Status.active')]]);
                $user = $users->patchEntity($user, $this->request->data, ['validate' => 'changePassword']);
                if (empty($user->errors())) {
                    $user->password = md5($user->password);
                    $users->save($user);
                    if ($user->id == $sessionData['id']) {
                        $this->AccessControl->setUser($user->toArray(), false);
                    }
                    $this->Flash->success(__('Password has been updated sucessfully.'));
                }
            }

            return $this->redirect(['_name' => 'account-profile']);
        }

        $isClient = false;
        if (Configure::read('Role.clients') == $sessionData['role_id']) {
            $isClient = true;
        }
        $accountSettingActive = 1;
        $defaultActiveTab = !empty($this->request->pass[0]) ? $this->request->pass[0] : '';
        $this->set(compact('timeZoneList', 'userDetails', 'accountSettingActive', 'id', 'defaultActiveTab', 'designationsList', 'isClient'));
        $this->set('title', [__('Account Setting'), __('User Profile')]);
        $this->pageNavigation = [
            'users' => [
                'title'     => __('User Profile'),
                'routeName' => 'account-profile',
            ],
            'view' => [
                'title'  => h('Account Setting'),
                'active' => true,
            ],
        ];
    }

    /**
     * Account setting.
     *
     * @param type $id user id
     *
     * @return \Cake\Http\Response|void
     */
    public function accountSetting($id = null)
    {
        $sessionData = $this->AccessControl->_user;
        if (empty($id)) {
            $id = $sessionData['id'];
        }
        $users = TableRegistry::get('Users');
        $userDetails = $users->get($id, ['contain' => ['Roles' => ['fields' => ['id', 'name']], 'Departments' => ['fields' => ['id', 'name'], 'joinType' => 'Left'], 'ProjectsUsers' => ['fields' => ['id', 'user_id']], 'TasksUsers' => ['fields' => ['id', 'user_id']]]], ['conditions' => ['status' => Configure::read('Status.active')]]);

        if ($this->request->is(['put', 'post', 'patch'])) {
            $user = $users->patchEntity($userDetails, $this->request->data, ['validate' => 'editProfile']);

            if (empty($user->errors())) {
                $users->save($user);
                $this->Flash->success(__('Profile has been updated sucessfully.'));
                if ($user->id == $sessionData['id']) {
                    $this->AccessControl->setUser($user->toArray(), false);

                    return $this->redirect(['_name' => 'account-profile']);
                }

                return $this->redirect('/users/'.$id);
            }
        }
        $accountSettingActive = 1;
        $this->set(compact('userDetails', 'accountSettingActive', 'id'));
        $this->set('title', [__('Account Setting')]);
        $this->pageNavigation = [
            'view' => [
                'title'  => h('Account Setting'),
                'active' => true,
            ],
        ];
    }

    /**
     * Check right password for admin.
     *
     * @return \Cake\Http\Response|void
     */
    public function checkPassword()
    {
        if (!$this->request->is('ajax')) {
            throw new NotFoundException();
        }
        $this->viewBuilder()->layout('ajax')->helpers(['AccessControl']);

        try {
            $profiles = TableRegistry::get('Users');
            $data = $profiles->find()->where(['Users.password' => md5($this->request->data['current_password']), 'Users.id ' => $this->request->data['id']]);
            $flag = $data->count() > 0 ? true : false;
        } catch (\Exception $ex) {
            $flag = false;
        }
        $this->set('data', $flag);
        $this->set('_serialize', false);
        $this->render('/Generals/ajax_response/');
    }

    /**
     * Forgot password method.
     *
     * @return \Cake\Http\Response|void
     */
    public function forgotPassword()
    {
        if ($this->request->is('post') || $this->request->is('put')) {
            if (!empty($this->request->data['email'])) {
                $users = TableRegistry::get('Users');
                $userData = $users->find()
                        ->where(['email' => $this->request->data['email']])
                        ->where(['status' => Configure::read('Status.active')])
                        ->first();
                if (!empty($userData)) {
                    $token = md5(rand(10000, 99999));
                    $userData->reset_password_token = ($token);
                    unset($userData->password);
                    if ($users->save($userData)) {
                        if (Configure::read('EmailConfiguration.sendEmailFromThisServer')) {
                            $emailTemplate = TableRegistry::get('EmailTemplates');
                            $emailTemplateData = $emailTemplate->find()
                                    ->where(['slug' => Configure::read('EmailConfiguration.emailResetPassword')])
                                    ->first();
                            if (!empty($emailTemplateData)) {
                                try {
                                    $replacementArr['USER_NAME'] = $userData->first_name;
                                    $replacementArr['USER_EMAIL'] = $userData->email;
                                    $replacementArr['TOKEN'] = $token;
                                    $replacementArr['LOGIN_PAGE_LINK'] = '<a href="'.Router::url('/account/login', true).'" title="Click to login" target="_blank">'.Router::url('/account/login', true).'</a>';
                                    $replacementArr['CHANGE_PASSWORD_LINK'] = '<a href="'.Router::url('/account/reset-password/'.$token, true).'" title="Click to change your password" target="_blank"> Click here.</a>';

                                    $EmailSubject = $this->Common->replaceEmailContent($emailTemplateData->subject, $replacementArr);
                                    $EmailContent = $this->Common->replaceEmailContent($emailTemplateData->template_text, $replacementArr);

                                    $email = new Email(Configure::read('EmailConfiguration.emailTemplate'));
                                    $email->template('default', '')
                                            ->from([Configure::read('EmailConfiguration.fromEmailAddress') => Configure::read('EmailConfiguration.fromEmailName')])
                                            ->emailFormat('both')
                                            ->to($userData->email)
                                            ->subject($EmailSubject)
                                            ->viewVars(['content' => $EmailContent])
                                            ->send();
                                    $this->Flash->set(__('A password reset link has been sent to your email.'), ['element' => 'success']);
                                } catch (\Exception $e) {
                                    $this->Flash->error(__('Please try again after some time.'));
                                }
                            }
                        }

                        return $this->redirect('/account/login');
                    } else {
                        $this->Flash->set(__('An error occured. Please, try again.'), ['element' => 'error']);
                    }
                } else {
                    $this->Flash->set(__('This email address is not registered with system.'), ['element' => 'error']);
                }
            } else {
                $this->Flash->set(__('Please enter email address.'), ['element' => 'error']);
            }
        }
        $this->set('title', [__('Forgot password')]);
        $this->viewBuilder()->layout('login');
    }

    /**
     * Check user email forgot password.
     *
     * @throws NotFoundException
     */
    public function checkEmailExists()
    {
        if (!$this->request->is('ajax')) {
            throw new NotFoundException();
        }

        try {
            $user = TableRegistry::get('Users');
            $data = $user->find()->where(['Users.email' => $this->request->data['email'], 'Users.status' => Configure::read('Status.active')]);
            $flag = $data->count() > 0 ? true : false;
        } catch (\Exception $ex) {
            $flag = false;
        }
        $this->set('data', $flag);
        $this->set('_serialize', false);
        $this->render('/Generals/ajax_response/');
    }

    /**
     * Reset password method.
     *
     * @return \Cake\Http\Response|void
     */
    public function resetPassword()
    {
        try {
            $this->viewBuilder()->layout('login');
            $resetPasswordToken = !empty($this->request->params['token']) ? $this->request->params['token'] : '';
            if (!empty($resetPasswordToken)) {
                $users = TableRegistry::get('Users');
                $userDetails = $users->find()
                        ->where(['reset_password_token' => $resetPasswordToken])
                        ->first();

                if (!empty($userDetails)) {
                    if ($this->request->is('post')) {
                        $userDetails->password = md5($this->request->data('password'));
                        $userDetails->reset_password_token = null;
                        if ($users->save($userDetails)) {
                            $this->Flash->success(__('Your password change successfully'));
                            $this->redirect(['_name' => 'account-login']);
                        } else {
                            $this->Flash->error(__('Your password not change.'));
                            $this->redirect(['_name' => 'account-login']);
                        }
                    }
                } else {
                    $this->Flash->error(__('Your reset password token has been expired. You can not change the password.'));
                    $this->redirect(['_name' => 'account-login']);
                }
            } else {
                $this->Flash->error(__('Password reset token mismatch.'));
                $this->redirect(['_name' => 'account-login']);
            }

            $this->set('resetPasswordToken', $resetPasswordToken);
            $this->set('viewTitle', 'MDPMS');
            $this->set('loginTypeTitle', 'Admin Login');
            $this->set('title', [__('Reset Password')]);
        } catch (NotFoundException $e) {
            $this->Flash->set(__('Invalid request.'), ['element' => 'error']);

            return $this->redirect(['_name' => 'account-login']);
        }
    }

    /**
     * Logout method.
     *
     * @return \Cake\Http\Response|void
     */
    public function logout()
    {
        $this->AccessControl->logout();

        return $this->redirect(Router::url(['_name' => 'account-login']));
    }
}
