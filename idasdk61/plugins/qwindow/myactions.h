
#include <QObject>

class MyActions : public QObject
{
  Q_OBJECT

public:
  MyActions(QObject *parent) : QObject(parent) {}

private slots:
  void clicked();

};
