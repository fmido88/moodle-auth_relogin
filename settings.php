<?php
// This file is part of Moodle - http://moodle.org/
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
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Admin settings and defaults.
 *
 * @package     auth_relogin
 * @copyright   2023 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die;

if ($hassiteconfig) {
    $settings->add(new admin_setting_heading('auth_relogin_settings',
                                                    get_string('pluginname', 'auth_relogin'),
                                                    get_string('plugin_desc', 'auth_relogin')));
    $settings->add(new admin_setting_configcheckbox('auth_relogin/loginpage',
                                                    get_string('loginpage', 'auth_relogin'),
                                                    get_string('loginpage_help', 'auth_relogin'),
                                                    1));

    $settings->add(new admin_setting_configcheckbox('auth_relogin/anypage',
                                                    get_string('anypage', 'auth_relogin'),
                                                    get_string('anypage_help', 'auth_relogin'),
                                                    1));
}
