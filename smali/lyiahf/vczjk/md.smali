.class public final synthetic Llyiahf/vczjk/md;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/text/Layout$TextInclusionStrategy;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/ke;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ke;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/md;->OooO00o:Llyiahf/vczjk/ke;

    return-void
.end method


# virtual methods
.method public final isSegmentInside(Landroid/graphics/RectF;Landroid/graphics/RectF;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/md;->OooO00o:Llyiahf/vczjk/ke;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/ke;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1
.end method
