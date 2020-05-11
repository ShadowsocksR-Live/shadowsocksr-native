//
//  ViewController.m
//  demo
//
//  Created by ssrlive on 2/12/18.
//  Copyright © 2018 ssrLive. All rights reserved.
//

#import "ViewController.h"
#import <pcre.h>

@interface ViewController ()
@property (strong, nonatomic) IBOutlet UITextView *patternText;
@property (strong, nonatomic) IBOutlet UITextView *subjectText;
@property (strong, nonatomic) IBOutlet UITextView *resultText;
@property (strong, nonatomic) IBOutlet UIButton *matchButton;

@end

@implementation ViewController

- (void) roundRectView:(UIView *)view {
    view.layer.cornerRadius = 7.;
    view.layer.borderWidth = .5;
    view.layer.borderColor = [UIColor lightGrayColor].CGColor;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    [self roundRectView:_patternText];
    [self roundRectView:_subjectText];
    [self roundRectView:_resultText];
    [self roundRectView:_matchButton];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(dismissKeyboard)];
    [self.view addGestureRecognizer:tap];
}

- (void) dismissKeyboard {
    [_patternText resignFirstResponder];
    [_subjectText resignFirstResponder];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)matchIt:(UIButton *)sender {
    _resultText.text = nil;
    pcre_main(_patternText.text.UTF8String,
              _subjectText.text.UTF8String,
              1,
              &out_put_imp,
              (__bridge void *)(self));
}

void out_put_imp(const char *info, void *p) {
    ViewController *obj = (__bridge ViewController *)p;
    NSString *result = obj.resultText.text;
    obj.resultText.text = [result stringByAppendingFormat:@"%s", info];
}

int pcre_main(const char *pattern, const char *subject, int find_all,
              void(*out_put_fn)(const char *info, void *p), void *p)
{
#define OVECCOUNT 30    /* should be a multiple of 3 */

    pcre *re;
    const char *error;
    unsigned char *name_table = NULL;
    unsigned int option_bits;
    int erroffset;
    int crlf_is_newline;
    int namecount;
    int name_entry_size = 0;
    int ovector[OVECCOUNT];
    int subject_length;
    int rc, i;
    int utf8;
    char out_buf[256] = { 0 };
    
    subject_length = (int)strlen(subject);
    
    /*************************************************************************
     * Now we are going to compile the regular expression pattern, and handle *
     * and errors that are detected.                                          *
     *************************************************************************/
    
    re = pcre_compile(pattern,              /* the pattern */
                      0,                    /* default options */
                      &error,               /* for error message */
                      &erroffset,           /* for error offset */
                      NULL);                /* use default character tables */
    
    /* Compilation failed: print the error message and exit */
    
    if (re == NULL) {
        sprintf(out_buf, "PCRE compilation failed at offset %d: %s\n", erroffset, error);
        out_put_fn(out_buf, p);
        return 1;
    }
    
    /*************************************************************************
     * If the compilation succeeded, we call PCRE again, in order to do a     *
     * pattern match against the subject string. This does just ONE match. If *
     * further matching is needed, it will be done below.                     *
     *************************************************************************/
    
    rc = pcre_exec(re,                   /* the compiled pattern */
                   NULL,                 /* no extra data - we didn't study the pattern */
                   subject,              /* the subject string */
                   subject_length,       /* the length of the subject */
                   0,                    /* start at offset 0 in the subject */
                   0,                    /* default options */
                   ovector,              /* output vector for substring information */
                   OVECCOUNT);           /* number of elements in the output vector */
    
    /* Matching failed: handle error cases */
    
    if (rc < 0) {
        switch(rc) {
            case PCRE_ERROR_NOMATCH:
                sprintf(out_buf, "No match\n");
                out_put_fn(out_buf, p);
                break;
                /*
                 Handle other special cases if you like
                 */
            default:
                sprintf(out_buf, "Matching error %d\n", rc);
                out_put_fn(out_buf, p);
                break;
        }
        pcre_free(re);     /* Release memory used for the compiled pattern */
        return 1;
    }
    
    /* Match succeded */
    
    sprintf(out_buf, "\nMatch succeeded at offset %d\n", ovector[0]);
    out_put_fn(out_buf, p);
    
    /*************************************************************************
     * We have found the first match within the subject string. If the output *
     * vector wasn't big enough, say so. Then output any substrings that were *
     * captured.                                                              *
     *************************************************************************/
    
    /* The output vector wasn't big enough */
    
    if (rc == 0) {
        rc = OVECCOUNT/3;
        sprintf(out_buf, "ovector only has room for %d captured substrings\n", rc - 1);
        out_put_fn(out_buf, p);
    }
    
    /* Show substrings stored in the output vector by number. Obviously, in a real
     application you might want to do things other than print them. */
    
    for (i = 0; i < rc; i++) {
        const char *substring_start = subject + ovector[2*i];
        int substring_length = ovector[2*i+1] - ovector[2*i];
        sprintf(out_buf, "%2d: %.*s\n", i, substring_length, substring_start);
        out_put_fn(out_buf, p);
    }
    
    
    /**************************************************************************
     * That concludes the basic part of this demonstration program. We have    *
     * compiled a pattern, and performed a single match. The code that follows *
     * shows first how to access named substrings, and then how to code for    *
     * repeated matches on the same subject.                                   *
     **************************************************************************/
    
    /* See if there are any named substrings, and if so, show them by name. First
     we have to extract the count of named parentheses from the pattern. */
    
    (void)pcre_fullinfo(re,                   /* the compiled pattern */
                        NULL,                 /* no extra data - we didn't study the pattern */
                        PCRE_INFO_NAMECOUNT,  /* number of named substrings */
                        &namecount);          /* where to put the answer */
    
    if (namecount <= 0) {
        sprintf(out_buf, "No named substrings\n");
        out_put_fn(out_buf, p);
    } else {
        unsigned char *tabptr;
        sprintf(out_buf, "Named substrings\n");
        out_put_fn(out_buf, p);

        /* Before we can access the substrings, we must extract the table for
         translating names to numbers, and the size of each entry in the table. */
        
        (void)pcre_fullinfo(re,                       /* the compiled pattern */
                            NULL,                     /* no extra data - we didn't study the pattern */
                            PCRE_INFO_NAMETABLE,      /* address of the table */
                            &name_table);             /* where to put the answer */
        
        (void)pcre_fullinfo(re,                       /* the compiled pattern */
                            NULL,                     /* no extra data - we didn't study the pattern */
                            PCRE_INFO_NAMEENTRYSIZE,  /* size of each entry in the table */
                            &name_entry_size);        /* where to put the answer */
        
        /* Now we can scan the table and, for each entry, print the number, the name,
         and the substring itself. */
        
        tabptr = name_table;
        for (i = 0; i < namecount; i++) {
            int n = (tabptr[0] << 8) | tabptr[1];
            sprintf(out_buf, "(%d) %*s: %.*s\n", n, name_entry_size - 3, tabptr + 2,
                   ovector[2*n+1] - ovector[2*n], subject + ovector[2*n]);
            out_put_fn(out_buf, p);
            tabptr += name_entry_size;
        }
    }
    
    
    /*************************************************************************
     * If the "-g" option was given on the command line, we want to continue  *
     * to search for additional matches in the subject string, in a similar   *
     * way to the /g option in Perl. This turns out to be trickier than you   *
     * might think because of the possibility of matching an empty string.    *
     * What happens is as follows:                                            *
     *                                                                        *
     * If the previous match was NOT for an empty string, we can just start   *
     * the next match at the end of the previous one.                         *
     *                                                                        *
     * If the previous match WAS for an empty string, we can't do that, as it *
     * would lead to an infinite loop. Instead, a special call of pcre_exec() *
     * is made with the PCRE_NOTEMPTY_ATSTART and PCRE_ANCHORED flags set.    *
     * The first of these tells PCRE that an empty string at the start of the *
     * subject is not a valid match; other possibilities must be tried. The   *
     * second flag restricts PCRE to one match attempt at the initial string  *
     * position. If this match succeeds, an alternative to the empty string   *
     * match has been found, and we can print it and proceed round the loop,  *
     * advancing by the length of whatever was found. If this match does not  *
     * succeed, we still stay in the loop, advancing by just one character.   *
     * In UTF-8 mode, which can be set by (*UTF8) in the pattern, this may be *
     * more than one byte.                                                    *
     *                                                                        *
     * However, there is a complication concerned with newlines. When the     *
     * newline convention is such that CRLF is a valid newline, we must       *
     * advance by two characters rather than one. The newline convention can  *
     * be set in the regex by (*CR), etc.; if not, we must find the default.  *
     *************************************************************************/
    
    if (!find_all) {     /* Check for -g */
        pcre_free(re);   /* Release the memory used for the compiled pattern */
        return 0;        /* Finish unless -g was given */
    }
    
    /* Before running the loop, check for UTF-8 and whether CRLF is a valid newline
     sequence. First, find the options with which the regex was compiled; extract
     the UTF-8 state, and mask off all but the newline options. */
    
    (void)pcre_fullinfo(re, NULL, PCRE_INFO_OPTIONS, &option_bits);
    utf8 = option_bits & PCRE_UTF8;
    option_bits &= PCRE_NEWLINE_CR|PCRE_NEWLINE_LF|PCRE_NEWLINE_CRLF|
    PCRE_NEWLINE_ANY|PCRE_NEWLINE_ANYCRLF;
    
    /* If no newline options were set, find the default newline convention from the
     build configuration. */
    
    if (option_bits == 0) {
        int d;
        (void)pcre_config(PCRE_CONFIG_NEWLINE, &d);
        /* Note that these values are always the ASCII ones, even in
         EBCDIC environments. CR = 13, NL = 10. */
        option_bits = (d == 13)? PCRE_NEWLINE_CR :
        (d == 10)? PCRE_NEWLINE_LF :
        (d == (13<<8 | 10))? PCRE_NEWLINE_CRLF :
        (d == -2)? PCRE_NEWLINE_ANYCRLF :
        (d == -1)? PCRE_NEWLINE_ANY : 0;
    }
    
    /* See if CRLF is a valid newline sequence. */
    
    crlf_is_newline =
    option_bits == PCRE_NEWLINE_ANY ||
    option_bits == PCRE_NEWLINE_CRLF ||
    option_bits == PCRE_NEWLINE_ANYCRLF;
    
    /* Loop for second and subsequent matches */
    
    for (;;) {
        int options = 0;                 /* Normally no options */
        int start_offset = ovector[1];   /* Start at end of previous match */
        
        /* If the previous match was for an empty string, we are finished if we are
         at the end of the subject. Otherwise, arrange to run another match at the
         same point to see if a non-empty match can be found. */
        
        if (ovector[0] == ovector[1]) {
            if (ovector[0] == subject_length) { break; }
            options = PCRE_NOTEMPTY_ATSTART | PCRE_ANCHORED;
        }
        
        /* Run the next matching operation */
        
        rc = pcre_exec(re,                   /* the compiled pattern */
                       NULL,                 /* no extra data - we didn't study the pattern */
                       subject,              /* the subject string */
                       subject_length,       /* the length of the subject */
                       start_offset,         /* starting offset in the subject */
                       options,              /* options */
                       ovector,              /* output vector for substring information */
                       OVECCOUNT);           /* number of elements in the output vector */
        
        /* This time, a result of NOMATCH isn't an error. If the value in "options"
         is zero, it just means we have found all possible matches, so the loop ends.
         Otherwise, it means we have failed to find a non-empty-string match at a
         point where there was a previous empty-string match. In this case, we do what
         Perl does: advance the matching position by one character, and continue. We
         do this by setting the "end of previous match" offset, because that is picked
         up at the top of the loop as the point at which to start again.
         
         There are two complications: (a) When CRLF is a valid newline sequence, and
         the current position is just before it, advance by an extra byte. (b)
         Otherwise we must ensure that we skip an entire UTF-8 character if we are in
         UTF-8 mode. */
        
        if (rc == PCRE_ERROR_NOMATCH) {
            if (options == 0) { break; }                /* All matches found */
            ovector[1] = start_offset + 1;              /* Advance one byte */
            if (crlf_is_newline &&                      /* If CRLF is newline & */
                start_offset < subject_length - 1 &&    /* we are at CRLF, */
                subject[start_offset] == '\r' &&
                subject[start_offset + 1] == '\n')
            {
                ovector[1] += 1;                          /* Advance by one more. */
            } else if (utf8) {  /* Otherwise, ensure we advance a whole UTF-8*/
                while (ovector[1] < subject_length) {     /* character. */
                    if ((subject[ovector[1]] & 0xc0) != 0x80) { break; }
                    ovector[1] += 1;
                }
            }
            continue;    /* Go round the loop again */
        }
        
        /* Other matching errors are not recoverable. */
        
        if (rc < 0) {
            sprintf(out_buf, "Matching error %d\n", rc);
            out_put_fn(out_buf, p);
            pcre_free(re);    /* Release memory used for the compiled pattern */
            return 1;
        }
        
        /* Match succeded */
        
        sprintf(out_buf, "\nMatch succeeded again at offset %d\n", ovector[0]);
        out_put_fn(out_buf, p);

        /* The match succeeded, but the output vector wasn't big enough. */
        
        if (rc == 0) {
            rc = OVECCOUNT/3;
            sprintf(out_buf, "ovector only has room for %d captured substrings\n", rc - 1);
            out_put_fn(out_buf, p);
        }
        
        /* As before, show substrings stored in the output vector by number, and then
         also any named substrings. */
        
        for (i = 0; i < rc; i++) {
            const char *substring_start = subject + ovector[2*i];
            int substring_length = ovector[2*i+1] - ovector[2*i];
            sprintf(out_buf, "%2d: %.*s\n", i, substring_length, substring_start);
            out_put_fn(out_buf, p);
        }
        
        if (namecount <= 0) {
            sprintf(out_buf, "No named substrings\n");
            out_put_fn(out_buf, p);
        } else {
            unsigned char *tabptr = name_table;
            sprintf(out_buf, "Named substrings\n");
            out_put_fn(out_buf, p);
            for (i = 0; i < namecount; i++) {
                int n = (tabptr[0] << 8) | tabptr[1];
                sprintf(out_buf, "(%d) %*s: %.*s\n", n, name_entry_size - 3, tabptr + 2,
                       ovector[2*n+1] - ovector[2*n], subject + ovector[2*n]);
                out_put_fn(out_buf, p);
                tabptr += name_entry_size;
            }
        }
    }      /* End of loop to find second and subsequent matches */
    
    sprintf(out_buf, "\n");
    out_put_fn(out_buf, p);
    pcre_free(re);       /* Release memory used for the compiled pattern */
    return 0;
}

@end
