.class public final Llyiahf/vczjk/to3;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $hasIconRightsOverDescendants:Llyiahf/vczjk/dl7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/to3;->$hasIconRightsOverDescendants:Llyiahf/vczjk/dl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/vo3;

    iget-boolean p1, p1, Llyiahf/vczjk/vo3;->OooOoo:Z

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/to3;->$hasIconRightsOverDescendants:Llyiahf/vczjk/dl7;

    const/4 v0, 0x0

    iput-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOOO:Llyiahf/vczjk/b0a;

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    return-object p1
.end method
