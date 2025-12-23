.class public final Llyiahf/vczjk/pa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $focusDirection:I


# direct methods
.method public constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pa;->$focusDirection:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/d93;

    iget v0, p0, Llyiahf/vczjk/pa;->$focusDirection:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/d93;->o00000oO(I)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
