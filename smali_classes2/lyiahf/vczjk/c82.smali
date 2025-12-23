.class public final Llyiahf/vczjk/c82;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/e82;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/e82;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c82;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c82;->OooOOO:Llyiahf/vczjk/e82;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/c82;->OooOOO:Llyiahf/vczjk/e82;

    iget v1, p0, Llyiahf/vczjk/c82;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v1, v0, Llyiahf/vczjk/e82;->OooO0oO:Llyiahf/vczjk/al4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v1, "classDescriptor"

    iget-object v0, v0, Llyiahf/vczjk/e82;->OooOO0:Llyiahf/vczjk/h82;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/h82;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/o0O00000;

    invoke-virtual {v0}, Llyiahf/vczjk/o0O00000;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getSupertypes(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0

    :pswitch_0
    sget-object v1, Llyiahf/vczjk/e72;->OooOOO0:Llyiahf/vczjk/e72;

    sget-object v2, Llyiahf/vczjk/jg5;->OooO00o:Llyiahf/vczjk/tp3;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v2, Llyiahf/vczjk/g13;->OooOoo:Llyiahf/vczjk/g13;

    sget-object v3, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/r82;->OooO(Llyiahf/vczjk/e72;Llyiahf/vczjk/oe3;)Ljava/util/List;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
