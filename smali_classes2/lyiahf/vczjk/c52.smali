.class public final synthetic Llyiahf/vczjk/c52;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/app/AlarmManager$OnAlarmListener;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/d52;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/d52;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/c52;->OooO00o:Llyiahf/vczjk/d52;

    return-void
.end method


# virtual methods
.method public final onAlarm()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/c52;->OooO00o:Llyiahf/vczjk/d52;

    iget-object v1, v0, Llyiahf/vczjk/d52;->OooO0O0:Ljava/lang/String;

    const-string v2, "DelayHandler-"

    const-string v3, " execute callback: "

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/ix8;->OooOOO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/d52;->OooO0o0:Llyiahf/vczjk/oe3;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/d52;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/os/Handler;

    new-instance v2, Llyiahf/vczjk/oO0O00o0;

    const/16 v3, 0x17

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    const-wide/16 v3, 0x0

    invoke-virtual {v1, v2, v3, v4}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return-void
.end method
