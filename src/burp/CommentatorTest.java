package burp;

import static org.junit.Assert.*;
import static org.junit.matchers.JUnitMatchers.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class CommentatorTest {

	@Test
	public void testCompilationNoGroup() {
		MockErrorHandler meh = new MockErrorHandler();
		BurpExtender.handleRegexpCompilation(meh, "", 0);
		assertThat(meh.message, containsString("No group"));
		assertThat(meh.title, containsString("Missing group"));
	}

	@Test
	public void testCompilationSyntaxError() {
		MockErrorHandler meh = new MockErrorHandler();
		BurpExtender.handleRegexpCompilation(meh, "([a)", 0);
		assertThat(meh.title, containsString("Syntax error"));
	}

	private static class MockErrorHandler implements BurpExtender.ErrorHandler {

		public String message = null, title = null;

		public void displayMessage(String message, String title) {
			this.message = message;
			this.title = title;
		}
	}
}
