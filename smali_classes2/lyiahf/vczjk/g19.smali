.class public final Llyiahf/vczjk/g19;
.super Llyiahf/vczjk/p3a;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0OO:I

.field public final synthetic OooO0Oo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/g19;->OooO0OO:I

    iput-object p1, p0, Llyiahf/vczjk/g19;->OooO0Oo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g19;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Llyiahf/vczjk/g5a;->OooO00o()Z

    move-result v0

    return v0

    :pswitch_0
    const/4 v0, 0x0

    return v0

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o0()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g19;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Llyiahf/vczjk/g5a;->OooO0o0()Z

    move-result v0

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/g19;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/util/Map;

    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0oO(Llyiahf/vczjk/n3a;)Llyiahf/vczjk/z4a;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/g19;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g19;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/z4a;

    return-object p1

    :pswitch_0
    const-string v0, "key"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/g19;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p1

    const-string v0, "null cannot be cast to non-null type org.jetbrains.kotlin.descriptors.TypeParameterDescriptor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/t4a;

    invoke-static {p1}, Llyiahf/vczjk/l5a;->OooOO0(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
