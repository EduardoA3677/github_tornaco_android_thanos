.class public final synthetic Llyiahf/vczjk/m71;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ze3;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/e71;

.field public final synthetic OooOOOo:Z

.field public final synthetic OooOOo0:Llyiahf/vczjk/oj2;


# direct methods
.method public synthetic constructor <init>(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/e71;ZLlyiahf/vczjk/oj2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/m71;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/m71;->OooOOO:Llyiahf/vczjk/ze3;

    iput-object p3, p0, Llyiahf/vczjk/m71;->OooOOOO:Llyiahf/vczjk/e71;

    iput-boolean p4, p0, Llyiahf/vczjk/m71;->OooOOOo:Z

    iput-object p5, p0, Llyiahf/vczjk/m71;->OooOOo0:Llyiahf/vczjk/oj2;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    iget-boolean v0, p0, Llyiahf/vczjk/m71;->OooOOO0:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/m71;->OooOOOo:Z

    xor-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/m71;->OooOOO:Llyiahf/vczjk/ze3;

    iget-object v2, p0, Llyiahf/vczjk/m71;->OooOOOO:Llyiahf/vczjk/e71;

    invoke-interface {v1, v2, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/m71;->OooOOo0:Llyiahf/vczjk/oj2;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/oj2;->OooO00o(Z)V

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
