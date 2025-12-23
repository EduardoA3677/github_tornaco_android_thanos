.class public final Llyiahf/vczjk/ke;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $inclusionStrategy:Llyiahf/vczjk/nl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nl9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ke;->$inclusionStrategy:Llyiahf/vczjk/nl9;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Landroid/graphics/RectF;

    check-cast p2, Landroid/graphics/RectF;

    iget-object v0, p0, Llyiahf/vczjk/ke;->$inclusionStrategy:Llyiahf/vczjk/nl9;

    invoke-static {p1}, Llyiahf/vczjk/dl6;->OooOOo0(Landroid/graphics/RectF;)Llyiahf/vczjk/wj7;

    move-result-object p1

    invoke-static {p2}, Llyiahf/vczjk/dl6;->OooOOo0(Landroid/graphics/RectF;)Llyiahf/vczjk/wj7;

    move-result-object p2

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/nl9;->OooO00o(Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
