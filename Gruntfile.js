module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    
    bower: {
      install: {
        options: {
          install: true,
          layout: 'byComponent',
          targetDir: 'source/src/assets/lib',
          cleanTargetDir: true, 
          copy: true
        }
      }
    },
    
    jasmine: {
        
          src: 'source/src/assets/*.js',
          options: {
            //keepRunner: true,
            version: '2.0.0',
            specs: 'source/tests/unit/specs/*_test.js',
            vendor: [
                "source/src/assets/lib/jsrsasign/js/jsrsasign-4.7.0-all-min.js",
                "source/src/assets/lib/jsjws/js/json-sans-eval.js",
                "source/src/assets/lib/jsjws/js/jws-3.0.js",
                "source/src/assets/lib/jquery/js/jquery.min.js",
                "source/src/assets/lib/jsjws.patch.js",
            ],
            helpers: 'source/tests/unit/helpers/*_helper.js'
          }
        
      }
  });
    
  // Load the plugins which are defined as devDependincies in the package.json
  require('load-grunt-tasks')(grunt, { scope: 'devDependencies' });

  // Default task(s).
  grunt.registerTask('depends', ['bower:install']);
};
