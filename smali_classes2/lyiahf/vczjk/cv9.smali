.class public final enum Llyiahf/vczjk/cv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "BeforeAttributeName"

    const/16 v1, 0x21

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 4

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result v0

    sget-object v1, Llyiahf/vczjk/rw9;->OoooO:Llyiahf/vczjk/dv9;

    if-eqz v0, :cond_4

    const/16 v2, 0x20

    if-eq v0, v2, :cond_3

    const/16 v2, 0x22

    if-eq v0, v2, :cond_2

    const/16 v2, 0x27

    if-eq v0, v2, :cond_2

    const/16 v2, 0x2f

    if-eq v0, v2, :cond_1

    sget-object v2, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    const v3, 0xffff

    if-eq v0, v3, :cond_0

    const/16 v3, 0x9

    if-eq v0, v3, :cond_3

    const/16 v3, 0xa

    if-eq v0, v3, :cond_3

    const/16 v3, 0xc

    if-eq v0, v3, :cond_3

    const/16 v3, 0xd

    if-eq v0, v3, :cond_3

    packed-switch v0, :pswitch_data_0

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {v0}, Llyiahf/vczjk/pt9;->OooOOoo()V

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOo0()V

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :pswitch_0
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0O()V

    iput-object v2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iput-object v2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    sget-object p2, Llyiahf/vczjk/rw9;->OoooOoo:Llyiahf/vczjk/lv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    :pswitch_1
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p2}, Llyiahf/vczjk/pt9;->OooOOoo()V

    iget-object p2, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/pt9;->OooOOO0(C)V

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    :cond_3
    return-void

    :cond_4
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {v0}, Llyiahf/vczjk/pt9;->OooOOoo()V

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOo0()V

    iput-object v1, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :pswitch_data_0
    .packed-switch 0x3c
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
