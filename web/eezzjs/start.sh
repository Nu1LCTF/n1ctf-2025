if [ -n "$FLAG" ]; then
  echo $FLAG > /flag
else
  echo "hh";
fi


su -c "node /app/app.js" node