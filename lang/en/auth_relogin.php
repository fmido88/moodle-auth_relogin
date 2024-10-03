<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Plugin strings are defined here.
 *
 * @package     auth_relogin
 * @category    string
 * @copyright   2023 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['cookies'] = 'Permanent cookies?';
$string['cookies_help'] = 'If enabled? this plugin will save cookies in users device to help it to re-login again to the website if the user\'s session isn\'t timed out yet,
 else if not enabled the plugin will try to re-login the users by the ip address which is not grantee.<br>
Warning: Permanent cookies may be considered a privacy issue if used without consent.<br>
NOTE: if both this method (permanent cookies) and (use ip address) not checked, this plugin not functionally working.';
$string['loginpage'] = 'Apply for login page?';
$string['loginpage_help'] = 'If checked the plugin will try to login the user automatically if their session not expired yet, otherwise the plugin works for any other page that requires login.';
$string['anypage'] = 'Login the user from any page.';
$string['anypage_help'] = 'If not enabled, the user will be logged in automatically only from pages required login, else it will login the user from any page including the login page.';
$string['pluginname'] = 'ReLogin';
$string['plugin_desc'] = 'Moodle uses session cookies only which will be deleted if the user closed the browser or the browser tab becomes inactive. This plugin aims to store a permanent cookies which store the session id to re-login the user again automatically only if the session hasn\'t timed out yet, so make sure to set the setting sessiontimeout to a proper value';
