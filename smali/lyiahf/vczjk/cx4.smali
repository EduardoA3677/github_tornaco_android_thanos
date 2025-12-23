.class public final Llyiahf/vczjk/cx4;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;
.implements Llyiahf/vczjk/gi3;
.implements Llyiahf/vczjk/ex4;
.implements Llyiahf/vczjk/l52;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/fx4;

.field public OooOoo:Llyiahf/vczjk/mk9;

.field public OooOoo0:Llyiahf/vczjk/lx4;

.field public final OooOooO:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fx4;Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    iput-object p2, p0, Llyiahf/vczjk/cx4;->OooOoo0:Llyiahf/vczjk/lx4;

    iput-object p3, p0, Llyiahf/vczjk/cx4;->OooOoo:Llyiahf/vczjk/mk9;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cx4;->OooOooO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooOoO0(Llyiahf/vczjk/v16;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cx4;->OooOooO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final o000OOo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/fx4;->OooO(Llyiahf/vczjk/cx4;)V

    return-void
.end method

.method public final o0O0O00()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    iget-object v1, v0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    const-string v1, "Expected textInputModifierNode to be null"

    invoke-static {v1}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :goto_0
    iput-object p0, v0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    return-void
.end method
