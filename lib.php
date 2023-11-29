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
 * Auth relogin lib.
 *
 * @package     auth_relogin
 * @copyright   2023 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Fire up  each time $CFG load.
 * @return void
 */
function auth_relogin_after_config() {
    if (!get_config('auth_relogin', 'anypage')) {
        return;
    }
    auth_relogin_apply_login();
}

/**
 * Fire up each time require_login() called and redirect non-confirmed users to confirm page.
 * @return void
 */
function auth_relogin_after_require_login() {
    auth_relogin_apply_login();
}

/**
 * Apply re-logging in the user using cookies.
 */
function auth_relogin_apply_login() {
    if (!is_enabled_auth('relogin')) {
        return;
    }

    if (CLI_SCRIPT || AJAX_SCRIPT) {
        return;
    }

    if (!isloggedin() || isguestuser()) {
        $auth = get_auth_plugin('relogin');
        if ($auth->pre_loginpage_hook() && !AJAX_SCRIPT) {
            global $CFG, $SESSION;
            if (!empty($SESSION->wantsurl)) {
                redirect($SESSION->wantsurl);
            }
        }
    }
}
