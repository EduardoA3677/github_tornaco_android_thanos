.class public final Llyiahf/vczjk/iq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $handwritingEnabled:Z

.field final synthetic $legacyTextInputServiceAdapter:Llyiahf/vczjk/fx4;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/fx4;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/iq1;->$handwritingEnabled:Z

    iput-object p2, p0, Llyiahf/vczjk/iq1;->$legacyTextInputServiceAdapter:Llyiahf/vczjk/fx4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/iq1;->$handwritingEnabled:Z

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/iq1;->$legacyTextInputServiceAdapter:Llyiahf/vczjk/fx4;

    check-cast v0, Llyiahf/vczjk/td;

    invoke-virtual {v0}, Llyiahf/vczjk/td;->OooOO0()Llyiahf/vczjk/os5;

    move-result-object v0

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/jl8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jl8;->OooO0oo(Ljava/lang/Object;)Z

    :cond_0
    return-object v1
.end method
