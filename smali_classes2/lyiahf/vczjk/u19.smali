.class public final synthetic Llyiahf/vczjk/u19;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Lgithub/tornaco/android/thanos/db/start/StartRecord;


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;Lgithub/tornaco/android/thanos/db/start/StartRecord;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/u19;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/u19;->OooOOO:Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;

    iput-object p2, p0, Llyiahf/vczjk/u19;->OooOOOO:Lgithub/tornaco/android/thanos/db/start/StartRecord;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/u19;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/j48;

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/u19;->OooOOO:Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;

    iget-object v1, p0, Llyiahf/vczjk/u19;->OooOOOO:Lgithub/tornaco/android/thanos/db/start/StartRecord;

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOOO0(Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;Lgithub/tornaco/android/thanos/db/start/StartRecord;Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/u19;->OooOOO:Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;

    iget-object v1, p0, Llyiahf/vczjk/u19;->OooOOOO:Lgithub/tornaco/android/thanos/db/start/StartRecord;

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOO0O(Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;Lgithub/tornaco/android/thanos/db/start/StartRecord;Llyiahf/vczjk/j48;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
