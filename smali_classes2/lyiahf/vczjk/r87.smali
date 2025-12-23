.class public final synthetic Llyiahf/vczjk/r87;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Lnow/fortuitous/profile/ProfileService;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lnow/fortuitous/profile/ProfileService;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/r87;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/r87;->OooOOO:Lnow/fortuitous/profile/ProfileService;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/r87;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/nw7;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/r87;->OooOOO:Lnow/fortuitous/profile/ProfileService;

    iget-object v0, v0, Lnow/fortuitous/profile/ProfileService;->OooOo00:Llyiahf/vczjk/pb7;

    const/4 v1, 0x0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object p1

    const-string v2, "getName(...)"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/pb7;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/LinkedHashMap;

    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lnow/fortuitous/profile/RuleInfoExt;

    invoke-virtual {v3}, Lnow/fortuitous/profile/RuleInfoExt;->getRule()Llyiahf/vczjk/nw7;

    move-result-object v3

    invoke-interface {v3}, Llyiahf/vczjk/nw7;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-static {v3, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    move-object v1, v2

    :cond_1
    const/4 p1, 0x1

    if-eqz v1, :cond_2

    move v0, p1

    goto :goto_0

    :cond_2
    const/4 v0, 0x0

    :goto_0
    xor-int/2addr p1, v0

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :cond_3
    const-string p1, "ruleRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :pswitch_0
    check-cast p1, Ljava/lang/String;

    const-string v0, "label"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/p87;

    iget-object v1, p0, Llyiahf/vczjk/r87;->OooOOO:Lnow/fortuitous/profile/ProfileService;

    const/4 v2, 0x1

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/p87;-><init>(Lnow/fortuitous/profile/ProfileService;Ljava/lang/String;I)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
