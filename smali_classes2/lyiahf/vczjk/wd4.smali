.class public final Llyiahf/vczjk/wd4;
.super Llyiahf/vczjk/ng0;
.source "SourceFile"


# instance fields
.field public final OooOO0o:Ljava/lang/reflect/Method;


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Method;)V
    .locals 1

    const-string v0, "method"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wd4;->OooOO0o:Ljava/lang/reflect/Method;

    return-void
.end method


# virtual methods
.method public final OooOO0()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wd4;->OooOO0o:Ljava/lang/reflect/Method;

    invoke-static {v0}, Llyiahf/vczjk/xt6;->OooOo0(Ljava/lang/reflect/Method;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
