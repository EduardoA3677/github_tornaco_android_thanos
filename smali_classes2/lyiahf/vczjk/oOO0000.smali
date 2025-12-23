.class public final synthetic Llyiahf/vczjk/oOO0000;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl1;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:I

.field public final synthetic OooOOo0:Ljava/lang/Comparable;


# direct methods
.method public synthetic constructor <init>(ILandroid/content/ComponentName;Landroid/content/Intent;Ljava/lang/String;Llyiahf/vczjk/a;)V
    .locals 0

    const/4 p3, 0x1

    iput p3, p0, Llyiahf/vczjk/oOO0000;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p5, p0, Llyiahf/vczjk/oOO0000;->OooOOO:Llyiahf/vczjk/a;

    iput-object p4, p0, Llyiahf/vczjk/oOO0000;->OooOOOO:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/oOO0000;->OooOOo0:Ljava/lang/Comparable;

    iput p1, p0, Llyiahf/vczjk/oOO0000;->OooOOOo:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/a;Ljava/lang/String;ILjava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/oOO0000;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oOO0000;->OooOOO:Llyiahf/vczjk/a;

    iput-object p2, p0, Llyiahf/vczjk/oOO0000;->OooOOOO:Ljava/lang/String;

    iput p3, p0, Llyiahf/vczjk/oOO0000;->OooOOOo:I

    iput-object p4, p0, Llyiahf/vczjk/oOO0000;->OooOOo0:Ljava/lang/Comparable;

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 9

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/oOO0000;->OooOOo0:Ljava/lang/Comparable;

    iget v2, p0, Llyiahf/vczjk/oOO0000;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    move-object v5, p1

    check-cast v5, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    iget-object v4, p0, Llyiahf/vczjk/oOO0000;->OooOOO:Llyiahf/vczjk/a;

    sget-object p1, Llyiahf/vczjk/he0;->OooO00o:Llyiahf/vczjk/fo9;

    iget-object p1, v4, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object p1, p1, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    iget-boolean p1, p1, Llyiahf/vczjk/k07;->OooOO0:Z

    if-nez p1, :cond_0

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object p1

    iget-object v7, p0, Llyiahf/vczjk/oOO0000;->OooOOOO:Ljava/lang/String;

    invoke-static {v7, p1}, Lutil/ObjectsUtils;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_0

    new-instance v3, Llyiahf/vczjk/oOO0O0O0;

    move-object v6, v1

    check-cast v6, Landroid/content/ComponentName;

    iget v8, p0, Llyiahf/vczjk/oOO0000;->OooOOOo:I

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/oOO0O0O0;-><init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;Landroid/content/ComponentName;Ljava/lang/String;I)V

    new-instance p1, Llyiahf/vczjk/y51;

    invoke-direct {p1, v3, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :cond_0
    return-void

    :pswitch_0
    move-object v3, p1

    check-cast v3, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;

    iget-object v2, p0, Llyiahf/vczjk/oOO0000;->OooOOO:Llyiahf/vczjk/a;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getStartResult()Lgithub/tornaco/android/thanos/core/app/start/StartResult;

    move-result-object p1

    iget-boolean p1, p1, Lgithub/tornaco/android/thanos/core/app/start/StartResult;->res:Z

    iget-object v4, p0, Llyiahf/vczjk/oOO0000;->OooOOOO:Ljava/lang/String;

    iget v6, p0, Llyiahf/vczjk/oOO0000;->OooOOOo:I

    if-eqz p1, :cond_1

    sget-object p1, Llyiahf/vczjk/he0;->OooO00o:Llyiahf/vczjk/fo9;

    iget-object p1, v2, Llyiahf/vczjk/a;->OoooOoo:Ljava/util/HashSet;

    new-instance v5, Lgithub/tornaco/android/thanos/core/os/ProcessName;

    invoke-direct {v5, v4, v6}, Lgithub/tornaco/android/thanos/core/os/ProcessName;-><init>(Ljava/lang/String;I)V

    invoke-virtual {p1, v5}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    :cond_1
    iget-object p1, v2, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object p1, p1, Llyiahf/vczjk/fo9;->OooOoO:Llyiahf/vczjk/k07;

    iget-boolean p1, p1, Llyiahf/vczjk/k07;->OooOO0:Z

    if-nez p1, :cond_2

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;->getPackageName()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    move-object p1, v1

    new-instance v1, Llyiahf/vczjk/oOO0O0O0;

    move-object v5, p1

    check-cast v5, Ljava/lang/String;

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/oOO0O0O0;-><init>(Llyiahf/vczjk/a;Lgithub/tornaco/android/thanos/core/app/start/StartResultExt;Ljava/lang/String;Ljava/lang/String;I)V

    new-instance p1, Llyiahf/vczjk/y51;

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    :cond_2
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
