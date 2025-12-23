.class public final Llyiahf/vczjk/v83;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $focusDirection:I


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Llyiahf/vczjk/v83;->$focusDirection:I

    const/4 v0, 0x1

    invoke-direct {p0, v0}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/d93;

    iget v0, p0, Llyiahf/vczjk/v83;->$focusDirection:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/d93;->o00000oO(I)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
