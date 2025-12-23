.class public final synthetic Llyiahf/vczjk/qe6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/qe6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qe6;->OooOOO:Ljava/lang/String;

    iput p2, p0, Llyiahf/vczjk/qe6;->OooOOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/qe6;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/j48;

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/qe6;->OooOOO:Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/qe6;->OooOOOO:I

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOOoo(Ljava/lang/String;ILlyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/qe6;->OooOOO:Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/qe6;->OooOOOO:I

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOOOO(Ljava/lang/String;ILlyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/qe6;->OooOOO:Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/qe6;->OooOOOO:I

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooO0O0(Ljava/lang/String;ILlyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/qe6;->OooOOO:Ljava/lang/String;

    iget v1, p0, Llyiahf/vczjk/qe6;->OooOOOO:I

    invoke-static {v0, v1, p1}, Lgithub/tornaco/android/thanos/db/ops/OpsDao_Impl;->OooOO0(Ljava/lang/String;ILlyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
