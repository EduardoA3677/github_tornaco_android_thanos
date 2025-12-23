.class public final Llyiahf/vczjk/pq0;
.super Llyiahf/vczjk/g5a;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0O0:I

.field public final OooO0OO:Llyiahf/vczjk/g5a;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/g5a;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    iput-object p1, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Llyiahf/vczjk/g5a;->OooO00o()Z

    move-result v0

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO00o()Z

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0O0()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Llyiahf/vczjk/g5a;->OooO0O0()Z

    move-result v0

    return v0

    :pswitch_0
    const/4 v0, 0x1

    return v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "annotations"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object p1

    return-object p1

    :pswitch_0
    const-string v0, "annotations"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object p1

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p1

    instance-of v2, p1, Llyiahf/vczjk/t4a;

    if-eqz v2, :cond_0

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/t4a;

    :cond_0
    invoke-static {v0, v1}, Llyiahf/vczjk/os9;->OooOo00(Llyiahf/vczjk/z4a;Llyiahf/vczjk/t4a;)Llyiahf/vczjk/z4a;

    move-result-object v1

    :cond_1
    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "topLevelType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "position"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/g5a;->OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1

    :pswitch_0
    const-string v0, "topLevelType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "position"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/g5a;->OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0o0()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pq0;->OooO0O0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/pq0;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
