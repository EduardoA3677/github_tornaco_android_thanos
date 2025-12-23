.class public final Llyiahf/vczjk/i81;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $items:Ljava/util/List;

.field final synthetic $key:Llyiahf/vczjk/ze3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v1;Ljava/util/List;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/i81;->$key:Llyiahf/vczjk/ze3;

    iput-object p2, p0, Llyiahf/vczjk/i81;->$items:Ljava/util/List;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/i81;->$key:Llyiahf/vczjk/ze3;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/i81;->$items:Ljava/util/List;

    invoke-interface {v2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, v1, p1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
