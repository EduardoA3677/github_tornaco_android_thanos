.class public abstract Llyiahf/vczjk/o3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "Alarms"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/o3;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static OooO00o(Landroid/content/Context;Llyiahf/vczjk/jqa;I)V
    .locals 4

    const-string v0, "alarm"

    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/AlarmManager;

    sget-object v1, Llyiahf/vczjk/m41;->OooOOo:Ljava/lang/String;

    new-instance v1, Landroid/content/Intent;

    const-class v2, Landroidx/work/impl/background/systemalarm/SystemAlarmService;

    invoke-direct {v1, p0, v2}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    const-string v2, "ACTION_DELAY_MET"

    invoke-virtual {v1, v2}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {v1, p1}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    const/high16 v2, 0x24000000

    invoke-static {p0, p2, v1, v2}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    if-eqz p0, :cond_0

    if-eqz v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Cancelling existing alarm with (workSpecId, systemId) ("

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ", "

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string p1, ")"

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/o3;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Landroid/app/AlarmManager;->cancel(Landroid/app/PendingIntent;)V

    :cond_0
    return-void
.end method

.method public static OooO0O0(Landroid/content/Context;Landroidx/work/impl/WorkDatabase;Llyiahf/vczjk/jqa;J)V
    .locals 9

    invoke-virtual {p1}, Landroidx/work/impl/WorkDatabase;->OooO0o0()Llyiahf/vczjk/ld9;

    move-result-object v0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/ld9;->OoooOO0(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/kd9;

    move-result-object v1

    const/4 v2, 0x0

    const/high16 v3, 0xc000000

    const-string v4, "ACTION_DELAY_MET"

    const-class v5, Landroidx/work/impl/background/systemalarm/SystemAlarmService;

    const-string v6, "alarm"

    if-eqz v1, :cond_0

    iget p1, v1, Llyiahf/vczjk/kd9;->OooO0OO:I

    invoke-static {p0, p2, p1}, Llyiahf/vczjk/o3;->OooO00o(Landroid/content/Context;Llyiahf/vczjk/jqa;I)V

    invoke-virtual {p0, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/AlarmManager;

    sget-object v1, Llyiahf/vczjk/m41;->OooOOo:Ljava/lang/String;

    new-instance v1, Landroid/content/Intent;

    invoke-direct {v1, p0, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {v1, v4}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {v1, p2}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    invoke-static {p0, p1, v1, v3}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    if-eqz v0, :cond_1

    invoke-virtual {v0, v2, p3, p4, p0}, Landroid/app/AlarmManager;->setExact(IJLandroid/app/PendingIntent;)V

    return-void

    :cond_0
    new-instance v1, Llyiahf/vczjk/tg7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/tg7;-><init>(Landroidx/work/impl/WorkDatabase;)V

    new-instance v7, Llyiahf/vczjk/du3;

    invoke-direct {v7, v1, v2}, Llyiahf/vczjk/du3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v7}, Llyiahf/vczjk/ru7;->runInTransaction(Ljava/util/concurrent/Callable;)Ljava/lang/Object;

    move-result-object p1

    const-string v1, "workDatabase.runInTransa\u2026NAGER_ID_KEY) }\n        )"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    new-instance v1, Llyiahf/vczjk/kd9;

    iget-object v7, p2, Llyiahf/vczjk/jqa;->OooO00o:Ljava/lang/String;

    iget v8, p2, Llyiahf/vczjk/jqa;->OooO0O0:I

    invoke-direct {v1, v7, v8, p1}, Llyiahf/vczjk/kd9;-><init>(Ljava/lang/String;II)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ld9;->OoooOo0(Llyiahf/vczjk/kd9;)V

    invoke-virtual {p0, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/AlarmManager;

    sget-object v1, Llyiahf/vczjk/m41;->OooOOo:Ljava/lang/String;

    new-instance v1, Landroid/content/Intent;

    invoke-direct {v1, p0, v5}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {v1, v4}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    invoke-static {v1, p2}, Llyiahf/vczjk/m41;->OooO0OO(Landroid/content/Intent;Llyiahf/vczjk/jqa;)V

    invoke-static {p0, p1, v1, v3}, Landroid/app/PendingIntent;->getService(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    if-eqz v0, :cond_1

    invoke-virtual {v0, v2, p3, p4, p0}, Landroid/app/AlarmManager;->setExact(IJLandroid/app/PendingIntent;)V

    :cond_1
    return-void
.end method
