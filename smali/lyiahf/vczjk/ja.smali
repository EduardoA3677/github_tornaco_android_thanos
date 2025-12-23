.class public final Llyiahf/vczjk/ja;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $focusDirection:Llyiahf/vczjk/b83;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b83;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ja;->$focusDirection:Llyiahf/vczjk/b83;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/d93;

    iget-object v0, p0, Llyiahf/vczjk/ja;->$focusDirection:Llyiahf/vczjk/b83;

    iget v0, v0, Llyiahf/vczjk/b83;->OooO00o:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/d93;->o00000oO(I)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
