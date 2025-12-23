.class public final Llyiahf/vczjk/jo1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $colors:Llyiahf/vczjk/tn1;

.field final synthetic $contextMenuBuilderBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/tn1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jo1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/jo1;->$colors:Llyiahf/vczjk/tn1;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/q31;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p1

    and-int/lit8 p3, p1, 0x11

    const/16 v0, 0x10

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eq p3, v0, :cond_0

    move p3, v2

    goto :goto_0

    :cond_0
    move p3, v1

    :goto_0
    and-int/2addr p1, v2

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p1, p3, :cond_1

    new-instance p1, Llyiahf/vczjk/zn1;

    invoke-direct {p1}, Llyiahf/vczjk/zn1;-><init>()V

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    check-cast p1, Llyiahf/vczjk/zn1;

    iget-object p3, p0, Llyiahf/vczjk/jo1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/jo1;->$colors:Llyiahf/vczjk/tn1;

    iget-object v2, p1, Llyiahf/vczjk/zn1;->OooO00o:Llyiahf/vczjk/tw8;

    invoke-virtual {v2}, Llyiahf/vczjk/tw8;->clear()V

    invoke-interface {p3, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/zn1;->OooO00o(Llyiahf/vczjk/tn1;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
