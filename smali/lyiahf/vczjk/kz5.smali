.class public final Llyiahf/vczjk/kz5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $node:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/kz5;->$node:Llyiahf/vczjk/hl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/c0a;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean v0, v0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/kz5;->$node:Llyiahf/vczjk/hl7;

    iput-object p1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    const/4 p1, 0x0

    goto :goto_0

    :cond_0
    const/4 p1, 0x1

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1
.end method
