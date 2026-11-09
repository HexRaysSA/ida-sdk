
#include <QtWidgets>

class MyActions : public QObject
{
  Q_OBJECT

public:
  MyActions(QObject *_parent) : QObject(_parent) {}

private slots:
  void clicked();

};
