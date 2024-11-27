<?php

use Gomzyakov\CS\Config;
use Gomzyakov\CS\Finder;

// Routes for analysis with `php-cs-fixer`
$routes = [
    __DIR__ . '/src',
];

$rules = [
    'binary_operator_spaces'                 => [
        'default'   => 'align_single_space_minimal',
        'operators' => [
            '='  => 'align_single_space',
            '=>' => 'align_single_space',
            '??' => 'single_space',
        ],
    ],
    'cast_spaces'                            => false,
    'declare_equal_normalize'                => ['space' => 'none'],
    'declare_parentheses'                    => true,
    'method_argument_space'                  => false,
    'multiline_whitespace_before_semicolons' => true,
    'no_blank_lines_after_phpdoc'            => false,
    'not_operator_with_successor_space'      => false,
    'phpdoc_separation'                      => false,
    'phpdoc_summary'                         => false,
    'phpdoc_no_package'                      => false,
    'no_trailing_whitespace_in_comment'      => true,
    'no_alternative_syntax'                  => false,
    'indentation_type'                       => true,
    'statement_indentation'                  => false,
];

return Config::createWithFinder(Finder::createWithRoutes($routes), $rules);
