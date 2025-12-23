.class public final synthetic Llyiahf/vczjk/fe6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/no0;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/e86;

.field public final synthetic OooOOO0:Ljava/util/concurrent/Executor;

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/tr5;


# direct methods
.method public synthetic constructor <init>(Ljava/util/concurrent/Executor;Llyiahf/vczjk/e86;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/tr5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fe6;->OooOOO0:Ljava/util/concurrent/Executor;

    iput-object p2, p0, Llyiahf/vczjk/fe6;->OooOOO:Llyiahf/vczjk/e86;

    iput-object p3, p0, Llyiahf/vczjk/fe6;->OooOOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/fe6;->OooOOOo:Llyiahf/vczjk/le3;

    iput-object p5, p0, Llyiahf/vczjk/fe6;->OooOOo0:Llyiahf/vczjk/tr5;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/mo0;)Ljava/lang/Object;
    .locals 6

    new-instance v0, Llyiahf/vczjk/oOOO0OOO;

    iget-object v3, p0, Llyiahf/vczjk/fe6;->OooOOOo:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/fe6;->OooOOo0:Llyiahf/vczjk/tr5;

    iget-object v1, p0, Llyiahf/vczjk/fe6;->OooOOO:Llyiahf/vczjk/e86;

    iget-object v2, p0, Llyiahf/vczjk/fe6;->OooOOOO:Ljava/lang/String;

    move-object v5, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/oOOO0OOO;-><init>(Llyiahf/vczjk/e86;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/tr5;Llyiahf/vczjk/mo0;)V

    iget-object p1, p0, Llyiahf/vczjk/fe6;->OooOOO0:Ljava/util/concurrent/Executor;

    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
