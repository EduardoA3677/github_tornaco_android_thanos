.class public final Llyiahf/vczjk/ko1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $colors:Llyiahf/vczjk/tn1;

.field final synthetic $contextMenuBuilderBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ko1;->$colors:Llyiahf/vczjk/tn1;

    iput-object p2, p0, Llyiahf/vczjk/ko1;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/ko1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ko1;->$colors:Llyiahf/vczjk/tn1;

    iget-object v2, p0, Llyiahf/vczjk/ko1;->$modifier:Llyiahf/vczjk/kl5;

    new-instance p1, Llyiahf/vczjk/jo1;

    iget-object p2, p0, Llyiahf/vczjk/ko1;->$contextMenuBuilderBlock:Llyiahf/vczjk/oe3;

    invoke-direct {p1, p2, v1}, Llyiahf/vczjk/jo1;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/tn1;)V

    const p2, 0x44f1a924

    invoke-static {p2, p1, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    const/16 v5, 0x180

    const/4 v6, 0x0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/mo1;->OooO00o(Llyiahf/vczjk/tn1;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    goto :goto_1

    :cond_1
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
