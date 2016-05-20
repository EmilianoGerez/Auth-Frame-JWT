var gulp = require('gulp');
var jshint = require('gulp-jshint');
var browserSync = require('browser-sync').create();

var gulpconfig = require('./gulpconfig');

gulp.task('js-lint', function(){
    gulp
        .src(gulpconfig.jsFiles)
        .pipe(jshint())
        .pipe(jshint.reporter('default'))
        .pipe(browserSync.stream());
});

gulp.task('watch', function(){
    gulp.watch(gulpconfig.jsFiles, ['js-lint']);
});

gulp.task('serve', ['js-lint', 'watch'], function () {
    browserSync.init({
        server: {
            baseDir: './'
        }
    });
});

gulp.task('default', ['serve']);