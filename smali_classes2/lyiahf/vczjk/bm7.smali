.class public final synthetic Llyiahf/vczjk/bm7;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/bm7;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/bm7;

    const-string v4, "<init>(Ljava/lang/reflect/Method;)V"

    const/4 v5, 0x0

    const/4 v1, 0x1

    const-class v2, Llyiahf/vczjk/lm7;

    const-string v3, "<init>"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/bm7;->OooOOO:Llyiahf/vczjk/bm7;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Ljava/lang/reflect/Method;

    const-string v0, "p0"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/lm7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/lm7;-><init>(Ljava/lang/reflect/Method;)V

    return-object v0
.end method
