.class public final Llyiahf/vczjk/p83;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $focusDirection:I

.field final synthetic $requestFocusSuccess:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p83;->$requestFocusSuccess:Llyiahf/vczjk/hl7;

    iput p2, p0, Llyiahf/vczjk/p83;->$focusDirection:I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/d93;

    iget-object v0, p0, Llyiahf/vczjk/p83;->$requestFocusSuccess:Llyiahf/vczjk/hl7;

    iget v1, p0, Llyiahf/vczjk/p83;->$focusDirection:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/d93;->o00000oO(I)Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    iput-object p1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object p1, p0, Llyiahf/vczjk/p83;->$requestFocusSuccess:Llyiahf/vczjk/hl7;

    iget-object p1, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p1, Ljava/lang/Boolean;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
