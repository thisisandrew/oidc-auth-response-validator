module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    
    bower: {
      install: {
        options: {
          install: true,
          layout: 'byComponent',
          targetDir: 'source/src/ext',
          cleanTargetDir: true, 
          copy: true
        }
      }
    },
    
    jasmine: {
          src: ['source/src/*.js', 'source/src/lib/*.js'],
          options: {
            //keepRunner: true,
            version: '2.0.0',
            specs: 'source/tests/unit/specs/*_test.js',
            vendor: [
                "source/src/ext/jsrsasign/js/jsrsasign-4.7.0-all-min.js",
                "source/src/ext/jsjws/js/json-sans-eval.js",
                "source/src/ext/jsjws/js/jws-3.0.min.js",
                "source/src/ext/jquery/js/jquery.min.js",
                "source/src/lib/jsjws.patch.js",
            ],
            helpers: 'source/tests/unit/helpers/*_helper.js'
          }
    },
    
    clean: {
      example_app: ['source/examples/app/public/src']
    },
    
    copy: {
      example_src: {
        files: [
          { expand: true, cwd: 'source/src/', src: ['**'], dest: 'source/examples/app/public/src' }
        ]
      }
    },
    
    watch:{
      app:{
        files: ['source/examples/app/app.js']
      }
    }
    
  });
    
  // Load the plugins which are defined as devDependincies in the package.json
  require('load-grunt-tasks')(grunt, { scope: 'devDependencies' });
  
  grunt.registerTask('example_app', function(){
    grunt.task.run('clean:example_app');
    grunt.task.run('copy:example_src');
    
    grunt.task.run('server');
    grunt.task.run('watch:app');
    
  });
  
  grunt.registerTask('server', 'Start a custom web server', function() {
    grunt.log.writeln('Started web server on https://saserver1:3000');
    require('./source/examples/app/app.js').listen(3000);
  });
  
  grunt.registerTask('run_app', function () {
    grunt.util.spawn({
        cmd: "node",
        args: ['source/examples/app/app.js'],
    });
    
    grunt.task.run('watch');
  });
};
