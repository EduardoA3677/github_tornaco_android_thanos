.class public final synthetic Llyiahf/vczjk/kf0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/kf0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/kf0;->OooOOO:Ljava/lang/String;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/kf0;->OooOOO:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/kf0;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/af8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ve8;->Oooo0O0:Llyiahf/vczjk/ze8;

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    return-object v0

    :pswitch_0
    check-cast p1, Ljava/lang/String;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v0

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v2

    if-ge v0, v2, :cond_0

    goto :goto_0

    :cond_0
    move-object v1, p1

    goto :goto_0

    :cond_1
    invoke-static {v1, p1}, Llyiahf/vczjk/u81;->OooOO0o(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    :goto_0
    return-object v1

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOO0(Ljava/lang/String;Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {v1, p1}, Lgithub/tornaco/android/thanos/db/start/StartRecordDao_Impl;->OooOOOo(Ljava/lang/String;Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_4
    check-cast p1, Ljava/io/File;

    return-object v1

    :pswitch_5
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {v1, p1}, Lgithub/tornaco/android/thanos/db/ops/OpsDao_Impl;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {v1, p1}, Lgithub/tornaco/android/thanos/db/n/NRDao_Impl;->OooO(Ljava/lang/String;Llyiahf/vczjk/j48;)Ljava/util/List;

    move-result-object p1

    return-object p1

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/j48;

    invoke-static {v1, p1}, Lgithub/tornaco/android/thanos/db/n/NRDao_Impl;->OooO0o0(Ljava/lang/String;Llyiahf/vczjk/j48;)Ljava/lang/Integer;

    move-result-object p1

    return-object p1

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o0(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/ve8;->OooOOo:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0x9

    aget-object v2, v2, v3

    const/4 v2, 0x0

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-virtual {v1, p1, v2}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-object v0

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/h24;

    iget-object p1, p1, Llyiahf/vczjk/h24;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/cm4;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/cm4;

    const/4 v0, 0x1

    invoke-direct {p1, v1, v0, v0}, Llyiahf/vczjk/cm4;-><init>(Ljava/lang/String;ZZ)V

    return-object p1

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0Oo(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    const/4 v1, 0x5

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    return-object v0

    :pswitch_b
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0o0(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    return-object v0

    :pswitch_c
    check-cast p1, Llyiahf/vczjk/af8;

    invoke-static {p1, v1}, Llyiahf/vczjk/ye8;->OooO0Oo(Llyiahf/vczjk/af8;Ljava/lang/String;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
