.class public final Llyiahf/vczjk/xi;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/animation/tooling/ComposeAnimation;


# static fields
.field public static final OooO0Oo:Z


# instance fields
.field public final OooO00o:Llyiahf/vczjk/zw9;

.field public final OooO0O0:Llyiahf/vczjk/wl;

.field public final OooO0OO:Llyiahf/vczjk/gi;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    invoke-static {}, Landroidx/compose/animation/tooling/ComposeAnimationType;->values()[Landroidx/compose/animation/tooling/ComposeAnimationType;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v1, :cond_1

    aget-object v4, v0, v3

    invoke-virtual {v4}, Landroidx/compose/animation/tooling/ComposeAnimationType;->name()Ljava/lang/String;

    move-result-object v4

    const-string v5, "ANIMATE_X_AS_STATE"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v2, 0x1

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    sput-boolean v2, Llyiahf/vczjk/xi;->OooO0Oo:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/wl;Llyiahf/vczjk/zw9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p3, p0, Llyiahf/vczjk/xi;->OooO00o:Llyiahf/vczjk/zw9;

    iput-object p2, p0, Llyiahf/vczjk/xi;->OooO0O0:Llyiahf/vczjk/wl;

    iput-object p1, p0, Llyiahf/vczjk/xi;->OooO0OO:Llyiahf/vczjk/gi;

    sget-object p2, Landroidx/compose/animation/tooling/ComposeAnimationType;->ANIMATE_X_AS_STATE:Landroidx/compose/animation/tooling/ComposeAnimationType;

    invoke-virtual {p1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    const-string p2, "null cannot be cast to non-null type kotlin.Any"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p2}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    move-result-object p2

    if-eqz p2, :cond_0

    invoke-static {p2}, Llyiahf/vczjk/sy;->o0000O0O([Ljava/lang/Object;)Ljava/util/Set;

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/tp6;->Oooo0OO(Ljava/lang/Object;)Ljava/util/Set;

    return-void
.end method
