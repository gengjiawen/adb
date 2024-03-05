package adb.test.app1;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class OwnProcessActivity extends Activity
{
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView label = new TextView(this);
        label.setText("I am OwnProcessActivity!");

        setContentView(label);
    }
}