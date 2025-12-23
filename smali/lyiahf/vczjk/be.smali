.class public final Llyiahf/vczjk/be;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $expandedStates:Llyiahf/vczjk/ss5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ss5;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $scrollState:Llyiahf/vczjk/z98;

.field final synthetic $transformOriginState:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/be;->$expandedStates:Llyiahf/vczjk/ss5;

    iput-object p2, p0, Llyiahf/vczjk/be;->$transformOriginState:Llyiahf/vczjk/qs5;

    iput-object p3, p0, Llyiahf/vczjk/be;->$scrollState:Llyiahf/vczjk/z98;

    iput-object p4, p0, Llyiahf/vczjk/be;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p5, p0, Llyiahf/vczjk/be;->$content:Llyiahf/vczjk/bf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

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

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/be;->$expandedStates:Llyiahf/vczjk/ss5;

    iget-object v2, p0, Llyiahf/vczjk/be;->$transformOriginState:Llyiahf/vczjk/qs5;

    iget-object v3, p0, Llyiahf/vczjk/be;->$scrollState:Llyiahf/vczjk/z98;

    iget-object v4, p0, Llyiahf/vczjk/be;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v5, p0, Llyiahf/vczjk/be;->$content:Llyiahf/vczjk/bf3;

    const/16 v7, 0x30

    const/4 v8, 0x0

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/th5;->OooO00o(Llyiahf/vczjk/ss5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/z98;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    goto :goto_1

    :cond_1
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
