.class public final Llyiahf/vczjk/xv5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ku5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/xc8;

.field public final synthetic OooOOOO:Llyiahf/vczjk/r58;

.field public final synthetic OooOOOo:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOo0:Llyiahf/vczjk/p29;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/ku5;Llyiahf/vczjk/r58;Llyiahf/vczjk/qs5;Llyiahf/vczjk/p29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xv5;->OooOOO0:Llyiahf/vczjk/xc8;

    iput-object p2, p0, Llyiahf/vczjk/xv5;->OooOOO:Llyiahf/vczjk/ku5;

    iput-object p3, p0, Llyiahf/vczjk/xv5;->OooOOOO:Llyiahf/vczjk/r58;

    iput-object p4, p0, Llyiahf/vczjk/xv5;->OooOOOo:Llyiahf/vczjk/qs5;

    iput-object p5, p0, Llyiahf/vczjk/xv5;->OooOOo0:Llyiahf/vczjk/p29;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/kj;

    check-cast p2, Llyiahf/vczjk/ku5;

    check-cast p3, Llyiahf/vczjk/rf1;

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    iget-object p4, p0, Llyiahf/vczjk/xv5;->OooOOO0:Llyiahf/vczjk/xc8;

    iget-object p4, p4, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast p4, Llyiahf/vczjk/fw8;

    invoke-virtual {p4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p4

    iget-object v0, p0, Llyiahf/vczjk/xv5;->OooOOO:Llyiahf/vczjk/ku5;

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p4

    iget-object v0, p0, Llyiahf/vczjk/xv5;->OooOOOo:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_3

    if-eqz p4, :cond_0

    goto :goto_1

    :cond_0
    iget-object p4, p0, Llyiahf/vczjk/xv5;->OooOOo0:Llyiahf/vczjk/p29;

    invoke-interface {p4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/util/List;

    invoke-interface {p4}, Ljava/util/List;->size()I

    move-result v0

    invoke-interface {p4, v0}, Ljava/util/List;->listIterator(I)Ljava/util/ListIterator;

    move-result-object p4

    :cond_1
    invoke-interface {p4}, Ljava/util/ListIterator;->hasPrevious()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p4}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/ku5;

    invoke-static {p2, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_2
    const/4 v0, 0x0

    :goto_0
    move-object p2, v0

    check-cast p2, Llyiahf/vczjk/ku5;

    :cond_3
    :goto_1
    const/4 p4, 0x0

    check-cast p3, Llyiahf/vczjk/zf1;

    if-nez p2, :cond_4

    const p1, 0x650602c

    invoke-virtual {p3, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    :goto_2
    invoke-virtual {p3, p4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_4
    const v0, -0x5aa2918b

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v0, Llyiahf/vczjk/b6;

    const/16 v1, 0x19

    invoke-direct {v0, v1, p2, p1}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const p1, -0x4b4ff5b3

    invoke-static {p1, v0, p3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object p1

    const/16 v0, 0x180

    iget-object v1, p0, Llyiahf/vczjk/xv5;->OooOOOO:Llyiahf/vczjk/r58;

    invoke-static {p2, v1, p1, p3, v0}, Llyiahf/vczjk/nqa;->OooO0Oo(Llyiahf/vczjk/ku5;Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_2

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
