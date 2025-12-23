.class public final Llyiahf/vczjk/dp0;
.super Llyiahf/vczjk/ip0;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/rg0;


# instance fields
.field public final OooO0o:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Method;Ljava/lang/Object;)V
    .locals 2

    const-string v0, "method"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x4

    const/4 v1, 0x0

    invoke-direct {p0, p1, v1, v0}, Llyiahf/vczjk/ip0;-><init>(Ljava/lang/reflect/Method;ZI)V

    iput-object p2, p0, Llyiahf/vczjk/dp0;->OooO0o:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0Oo([Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    const-string v0, "args"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0, p1}, Llyiahf/vczjk/u34;->OooOO0O(Llyiahf/vczjk/so0;[Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/dp0;->OooO0o:Ljava/lang/Object;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/ip0;->OooO0oO([Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
