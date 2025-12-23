.class public final enum Llyiahf/vczjk/jv9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "AttributeValue_unquoted"

    const/16 v1, 0x27

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/rw9;->o000000:[C

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zt0;->OooO0oo([C)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    if-lez v1, :cond_0

    iget-object v1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/pt9;->OooOOOO(Ljava/lang/String;)V

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result p2

    if-eqz p2, :cond_6

    const/16 v0, 0x20

    if-eq p2, v0, :cond_5

    const/16 v0, 0x22

    if-eq p2, v0, :cond_4

    const/16 v0, 0x60

    if-eq p2, v0, :cond_4

    sget-object v0, Llyiahf/vczjk/rw9;->OooOOO0:Llyiahf/vczjk/mu9;

    const v1, 0xffff

    if-eq p2, v1, :cond_3

    const/16 v1, 0x9

    if-eq p2, v1, :cond_5

    const/16 v1, 0xa

    if-eq p2, v1, :cond_5

    const/16 v1, 0xc

    if-eq p2, v1, :cond_5

    const/16 v1, 0xd

    if-eq p2, v1, :cond_5

    const/16 v1, 0x26

    if-eq p2, v1, :cond_1

    const/16 v1, 0x27

    if-eq p2, v1, :cond_4

    packed-switch p2, :pswitch_data_0

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO(C)V

    return-void

    :pswitch_0
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooOO0O()V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    const/16 p2, 0x3e

    invoke-static {p2}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    move-result-object p2

    const/4 v0, 0x1

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/bu9;->OooO0OO(Ljava/lang/Character;Z)[I

    move-result-object p2

    if-eqz p2, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOOo([I)V

    return-void

    :cond_2
    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/pt9;->OooOOO(C)V

    return-void

    :cond_3
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOO0o(Llyiahf/vczjk/rw9;)V

    iput-object v0, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_4
    :pswitch_1
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO(C)V

    return-void

    :cond_5
    sget-object p2, Llyiahf/vczjk/rw9;->OoooO0O:Llyiahf/vczjk/cv9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_6
    invoke-virtual {p1, p0}, Llyiahf/vczjk/bu9;->OooOOO0(Llyiahf/vczjk/rw9;)V

    iget-object p1, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    const p2, 0xfffd

    invoke-virtual {p1, p2}, Llyiahf/vczjk/pt9;->OooOOO(C)V

    return-void

    :pswitch_data_0
    .packed-switch 0x3c
        :pswitch_1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
