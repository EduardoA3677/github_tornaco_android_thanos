.class public final Llyiahf/vczjk/i73;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $items:Llyiahf/vczjk/ws5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ws5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ws5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/i73;->$items:Llyiahf/vczjk/ws5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object p1, p0, Llyiahf/vczjk/i73;->$items:Llyiahf/vczjk/ws5;

    iget-object v0, p1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget p1, p1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p1, :cond_0

    aget-object v2, v0, v1

    check-cast v2, Llyiahf/vczjk/mf5;

    invoke-interface {v2}, Llyiahf/vczjk/mf5;->OooO0O0()V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
