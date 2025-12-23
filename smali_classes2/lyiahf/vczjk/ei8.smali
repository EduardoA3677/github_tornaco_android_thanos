.class public final synthetic Llyiahf/vczjk/ei8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cm4;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/cp8;

.field public final synthetic OooOOOo:Llyiahf/vczjk/yo9;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cm4;Llyiahf/vczjk/cp8;Llyiahf/vczjk/yo9;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/ei8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ei8;->OooOOO:Llyiahf/vczjk/cm4;

    iput-object p2, p0, Llyiahf/vczjk/ei8;->OooOOOO:Llyiahf/vczjk/cp8;

    iput-object p3, p0, Llyiahf/vczjk/ei8;->OooOOOo:Llyiahf/vczjk/yo9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/ei8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ei8;->OooOOO:Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_0

    const-string v0, "application/zip"

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    const/16 v1, 0x64

    iget-object v2, p0, Llyiahf/vczjk/ei8;->OooOOOO:Llyiahf/vczjk/cp8;

    invoke-virtual {v2, v0, v1}, Llyiahf/vczjk/cp8;->OooO0o0([Ljava/lang/String;I)V

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ei8;->OooOOOo:Llyiahf/vczjk/yo9;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ei8;->OooOOO:Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_1

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-static {v0, v1}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatForFileName(J)Ljava/lang/String;

    move-result-object v0

    const-string v1, "Thanox-Backup-"

    invoke-static {v1, v0}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, ".zip"

    invoke-static {v0, v1}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const-string v1, "application/zip"

    const/16 v2, 0x2706

    iget-object v3, p0, Llyiahf/vczjk/ei8;->OooOOOO:Llyiahf/vczjk/cp8;

    const/4 v4, 0x4

    invoke-static {v3, v1, v0, v2, v4}, Llyiahf/vczjk/cp8;->OooO0Oo(Llyiahf/vczjk/cp8;Ljava/lang/String;Ljava/lang/String;II)V

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ei8;->OooOOOo:Llyiahf/vczjk/yo9;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
