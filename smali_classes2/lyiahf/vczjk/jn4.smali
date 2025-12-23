.class public final Llyiahf/vczjk/jn4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $contentType:Llyiahf/vczjk/oe3;

.field final synthetic $items:Ljava/util/List;


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/mo2;->OooOoo:Llyiahf/vczjk/mo2;

    iput-object v0, p0, Llyiahf/vczjk/jn4;->$contentType:Llyiahf/vczjk/oe3;

    iput-object p1, p0, Llyiahf/vczjk/jn4;->$items:Ljava/util/List;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/jn4;->$contentType:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/jn4;->$items:Ljava/util/List;

    invoke-interface {v1, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
