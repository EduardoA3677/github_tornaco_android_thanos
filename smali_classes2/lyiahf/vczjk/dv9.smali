.class public final enum Llyiahf/vczjk/dv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "AttributeName"

    const/16 v1, 0x22

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/rw9;->o000OOo:[C

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooO0oo([C)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    iget-object v2, v1, Llyiahf/vczjk/pt9;->OooO0Oo:Ljava/lang/String;

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :goto_0
    iput-object v0, v1, Llyiahf/vczjk/pt9;->OooO0Oo:Ljava/lang/String;

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    if-eqz p2, :cond_5

    const/16 v0, 0x20

    if-eq p2, v0, :cond_4

    const/16 v0, 0x22

    if-eq p2, v0, :cond_3

    const/16 v0, 0x27

    if-eq p2, v0, :cond_3

    const/16 v0, 0x2f

    if-eq p2, v0, :cond_2

    sget-object v0, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    const v1, 0xffff

    if-eq p2, v1, :cond_1

    const/16 v1, 0x9

    if-eq p2, v1, :cond_4

    const/16 v1, 0xa

    if-eq p2, v1, :cond_4

    const/16 v1, 0xc

    if-eq p2, v1, :cond_4

    const/16 v1, 0xd

    if-eq p2, v1, :cond_4

    packed-switch p2, :pswitch_data_0

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO0(C)V

    return-void

    :pswitch_0
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0O()V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :pswitch_1
    sget-object p2, Llyiahf/vczjk/rw9;->o000oOoO:Llyiahf/vczjk/fv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_2
    sget-object p2, Llyiahf/vczjk/rw9;->OoooOoo:Llyiahf/vczjk/lv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_3
    :pswitch_2
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO0(C)V

    return-void

    :cond_4
    sget-object p2, Llyiahf/vczjk/rw9;->OoooOO0:Llyiahf/vczjk/ev9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_5
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    const p2, 0xfffd

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO0(C)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x3c
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
