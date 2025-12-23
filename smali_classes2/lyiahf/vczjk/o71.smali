.class public final synthetic Llyiahf/vczjk/o71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/b71;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:Z

.field public final synthetic OooOOoo:Z


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/b71;ZZLlyiahf/vczjk/oe3;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/o71;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/o71;->OooOOO:Llyiahf/vczjk/ze3;

    iput-object p3, p0, Llyiahf/vczjk/o71;->OooOOOO:Llyiahf/vczjk/b71;

    iput-boolean p4, p0, Llyiahf/vczjk/o71;->OooOOOo:Z

    iput-boolean p5, p0, Llyiahf/vczjk/o71;->OooOOo0:Z

    iput-object p6, p0, Llyiahf/vczjk/o71;->OooOOo:Llyiahf/vczjk/oe3;

    iput-boolean p7, p0, Llyiahf/vczjk/o71;->OooOOoo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    iget-boolean v0, p0, Llyiahf/vczjk/o71;->OooOOO0:Z

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/o71;->OooOOOo:Z

    xor-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/o71;->OooOOOO:Llyiahf/vczjk/b71;

    iget-object v2, p0, Llyiahf/vczjk/o71;->OooOOO:Llyiahf/vczjk/ze3;

    invoke-interface {v2, v1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/o71;->OooOOo0:Z

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Llyiahf/vczjk/o71;->OooOOoo:Z

    xor-int/lit8 v0, v0, 0x1

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/o71;->OooOOo:Llyiahf/vczjk/oe3;

    invoke-interface {v1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
