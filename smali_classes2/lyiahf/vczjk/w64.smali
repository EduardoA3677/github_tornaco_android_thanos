.class public final Llyiahf/vczjk/w64;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:Ljava/util/HashMap;

.field public static final OooO00o:Ljava/lang/String;

.field public static final OooO0O0:Ljava/lang/String;

.field public static final OooO0OO:Ljava/lang/String;

.field public static final OooO0Oo:Ljava/lang/String;

.field public static final OooO0o:Llyiahf/vczjk/hc3;

.field public static final OooO0o0:Llyiahf/vczjk/hy0;

.field public static final OooO0oO:Llyiahf/vczjk/hy0;

.field public static final OooO0oo:Ljava/util/HashMap;

.field public static final OooOO0:Ljava/util/HashMap;

.field public static final OooOO0O:Ljava/util/HashMap;

.field public static final OooOO0o:Ljava/util/HashMap;

.field public static final OooOOO:Ljava/util/List;

.field public static final OooOOO0:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 14

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Llyiahf/vczjk/xf3;->OooO0OO:Llyiahf/vczjk/xf3;

    iget-object v2, v1, Llyiahf/vczjk/bg3;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v2, 0x2e

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, v1, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Llyiahf/vczjk/yf3;->OooO0OO:Llyiahf/vczjk/yf3;

    iget-object v3, v1, Llyiahf/vczjk/bg3;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, v1, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO0O0:Ljava/lang/String;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Llyiahf/vczjk/ag3;->OooO0OO:Llyiahf/vczjk/ag3;

    iget-object v3, v1, Llyiahf/vczjk/bg3;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, v1, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO0OO:Ljava/lang/String;

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v1, Llyiahf/vczjk/zf3;->OooO0OO:Llyiahf/vczjk/zf3;

    iget-object v3, v1, Llyiahf/vczjk/bg3;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, v1, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO0Oo:Ljava/lang/String;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.jvm.functions.FunctionN"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO0o0:Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooO0o:Llyiahf/vczjk/hc3;

    sget-object v0, Llyiahf/vczjk/t09;->OooOOo0:Llyiahf/vczjk/hy0;

    sput-object v0, Llyiahf/vczjk/w64;->OooO0oO:Llyiahf/vczjk/hy0;

    const-class v0, Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooO0oo:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooOO0:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooOO0O:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooOO0o:Ljava/util/HashMap;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    sput-object v0, Llyiahf/vczjk/w64;->OooOOO0:Ljava/util/HashMap;

    sget-object v0, Llyiahf/vczjk/w09;->OooOoo0:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0O0:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    const/4 v5, 0x0

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v6, Llyiahf/vczjk/v64;

    const-class v1, Ljava/lang/Iterable;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v6, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOoOO:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v7, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/Iterator;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v7, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOoo:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0OO:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v8, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/Collection;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v8, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOooO:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0o0:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v9, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/List;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v9, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->Oooo000:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0oO:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v10, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/Set;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v10, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->OooOooo:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo0o:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v11, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/ListIterator;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v11, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    sget-object v0, Llyiahf/vczjk/w09;->Oooo00O:Llyiahf/vczjk/hc3;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/w09;->Oooo0oo:Llyiahf/vczjk/hc3;

    new-instance v4, Llyiahf/vczjk/hy0;

    iget-object v12, v1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v3, v12}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v3

    invoke-direct {v4, v12, v3, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v12, Llyiahf/vczjk/v64;

    const-class v3, Ljava/util/Map;

    invoke-static {v3}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v3

    invoke-direct {v12, v3, v1, v4}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Ooooo0o(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo00o:Llyiahf/vczjk/hc3;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/w09;->Oooo:Llyiahf/vczjk/hc3;

    new-instance v3, Llyiahf/vczjk/hy0;

    iget-object v4, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v4}, Llyiahf/vczjk/u34;->Ooooo0o(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;)Llyiahf/vczjk/hc3;

    move-result-object v1

    invoke-direct {v3, v4, v1, v5}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/hc3;Z)V

    new-instance v13, Llyiahf/vczjk/v64;

    const-class v1, Ljava/util/Map$Entry;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-direct {v13, v1, v0, v3}, Llyiahf/vczjk/v64;-><init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    filled-new-array/range {v6 .. v13}, [Llyiahf/vczjk/v64;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/w64;->OooOOO:Ljava/util/List;

    const-class v1, Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/w09;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/String;

    sget-object v3, Llyiahf/vczjk/w09;->OooO0o:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/CharSequence;

    sget-object v3, Llyiahf/vczjk/w09;->OooO0o0:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/Throwable;

    sget-object v3, Llyiahf/vczjk/w09;->OooOO0O:Llyiahf/vczjk/hc3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/hc3;)V

    const-class v1, Ljava/lang/Cloneable;

    sget-object v3, Llyiahf/vczjk/w09;->OooO0OO:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/Number;

    sget-object v3, Llyiahf/vczjk/w09;->OooO:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/Comparable;

    sget-object v3, Llyiahf/vczjk/w09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/hc3;)V

    const-class v1, Ljava/lang/Enum;

    sget-object v3, Llyiahf/vczjk/w09;->OooOO0:Llyiahf/vczjk/ic3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V

    const-class v1, Ljava/lang/annotation/Annotation;

    sget-object v3, Llyiahf/vczjk/w09;->OooOOoo:Llyiahf/vczjk/hc3;

    invoke-static {v1, v3}, Llyiahf/vczjk/w64;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/hc3;)V

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/v64;

    iget-object v3, v1, Llyiahf/vczjk/v64;->OooO00o:Llyiahf/vczjk/hy0;

    iget-object v4, v1, Llyiahf/vczjk/v64;->OooO0O0:Llyiahf/vczjk/hy0;

    invoke-static {v3, v4}, Llyiahf/vczjk/w64;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    iget-object v1, v1, Llyiahf/vczjk/v64;->OooO0OO:Llyiahf/vczjk/hy0;

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v6

    iget-object v6, v6, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    sget-object v7, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    invoke-virtual {v7, v6, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/w64;->OooOO0o:Ljava/util/HashMap;

    invoke-virtual {v3, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/w64;->OooOOO0:Ljava/util/HashMap;

    invoke-virtual {v3, v4, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v4}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v3

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v4

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    sget-object v6, Llyiahf/vczjk/w64;->OooOO0:Ljava/util/HashMap;

    invoke-virtual {v6, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v1, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    sget-object v3, Llyiahf/vczjk/w64;->OooOO0O:Ljava/util/HashMap;

    invoke-virtual {v3, v1, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    invoke-static {}, Llyiahf/vczjk/ee4;->values()[Llyiahf/vczjk/ee4;

    move-result-object v0

    array-length v1, v0

    move v3, v5

    :goto_1
    if-ge v3, v1, :cond_1

    aget-object v4, v0, v3

    invoke-virtual {v4}, Llyiahf/vczjk/ee4;->OooO0o()Llyiahf/vczjk/hc3;

    move-result-object v6

    const-string v7, "getWrapperFqName(...)"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v7, Llyiahf/vczjk/hy0;

    invoke-virtual {v6}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v8

    iget-object v6, v6, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v6}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-direct {v7, v8, v6}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ee4;->OooO0o0()Llyiahf/vczjk/q47;

    move-result-object v4

    const-string v6, "getPrimitiveType(...)"

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v4}, Llyiahf/vczjk/q47;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v4

    invoke-virtual {v6, v4}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object v4

    new-instance v6, Llyiahf/vczjk/hy0;

    invoke-virtual {v4}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v8

    iget-object v4, v4, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v4}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v4

    invoke-direct {v6, v8, v4}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-static {v7, v6}, Llyiahf/vczjk/w64;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    sget-object v0, Llyiahf/vczjk/r51;->OooO00o:Ljava/util/LinkedHashSet;

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/hy0;

    new-instance v3, Llyiahf/vczjk/hc3;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v6, "kotlin.jvm.internal."

    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-virtual {v6}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, "CompanionObject"

    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-direct {v3, v4}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v4, Llyiahf/vczjk/hy0;

    invoke-virtual {v3}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v6

    iget-object v3, v3, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v3

    invoke-direct {v4, v6, v3}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sget-object v3, Llyiahf/vczjk/vy8;->OooO0O0:Llyiahf/vczjk/qt5;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object v1

    invoke-static {v4, v1}, Llyiahf/vczjk/w64;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    goto :goto_2

    :cond_2
    move v0, v5

    :goto_3
    const/16 v1, 0x17

    if-ge v0, v1, :cond_3

    new-instance v1, Llyiahf/vczjk/hc3;

    const-string v3, "kotlin.jvm.functions.Function"

    invoke-static {v0, v3}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object v3

    invoke-direct {v1, v3}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/hy0;

    invoke-virtual {v1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v4

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-direct {v3, v4, v1}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    new-instance v1, Llyiahf/vczjk/hy0;

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v6, "Function"

    invoke-direct {v4, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-direct {v1, v6, v4}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-static {v3, v1}, Llyiahf/vczjk/w64;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    new-instance v1, Llyiahf/vczjk/hc3;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v4, Llyiahf/vczjk/w64;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-direct {v1, v3}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/w64;->OooO0oO:Llyiahf/vczjk/hy0;

    sget-object v4, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v4, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v0, v0, 0x1

    goto :goto_3

    :cond_3
    :goto_4
    const/16 v0, 0x16

    if-ge v5, v0, :cond_4

    sget-object v0, Llyiahf/vczjk/zf3;->OooO0OO:Llyiahf/vczjk/zf3;

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v3, v0, Llyiahf/vczjk/bg3;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v0, v0, Llyiahf/vczjk/bg3;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/hc3;

    new-instance v3, Ljava/lang/StringBuilder;

    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/w64;->OooO0oO:Llyiahf/vczjk/hy0;

    sget-object v3, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    iget-object v1, v1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v3, v1, v0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v5, v5, 0x1

    goto :goto_4

    :cond_4
    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicInt"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicLong"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicLong;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicBoolean"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicReference"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicIntArray"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicIntegerArray;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicLongArray"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicLongArray;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/hc3;

    const-string v1, "kotlin.concurrent.atomics.AtomicArray"

    invoke-direct {v0, v1}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    const-class v1, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/w09;->OooO0O0:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object v0

    const-class v1, Ljava/lang/Void;

    invoke-static {v1}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    sget-object v1, Llyiahf/vczjk/w64;->OooO0oo:Ljava/util/HashMap;

    invoke-virtual {v1, v0, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/hy0;->OooO00o()Llyiahf/vczjk/hc3;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    sget-object v0, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    invoke-virtual {v0, p1, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public static OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/hc3;)V
    .locals 2

    invoke-static {p0}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object p0

    const-string v0, "topLevelFqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/hy0;

    invoke-virtual {p1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {p1}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object p1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/w64;->OooO00o(Llyiahf/vczjk/hy0;Llyiahf/vczjk/hy0;)V

    return-void
.end method

.method public static OooO0OO(Ljava/lang/Class;Llyiahf/vczjk/ic3;)V
    .locals 0

    invoke-virtual {p1}, Llyiahf/vczjk/ic3;->OooO0oO()Llyiahf/vczjk/hc3;

    move-result-object p1

    invoke-static {p0, p1}, Llyiahf/vczjk/w64;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/hc3;)V

    return-void
.end method

.method public static OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;
    .locals 2

    invoke-virtual {p0}, Ljava/lang/Class;->isPrimitive()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Ljava/lang/Class;->isArray()Z

    move-result v0

    :cond_0
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/hc3;

    invoke-virtual {p0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object p0

    const-string v1, "getCanonicalName(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, p0}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    new-instance p0, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {p0, v1, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object p0

    :cond_1
    invoke-static {v0}, Llyiahf/vczjk/w64;->OooO0Oo(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object v0

    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object p0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/hy0;->OooO0Oo(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hy0;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0o(Llyiahf/vczjk/ic3;)Llyiahf/vczjk/hy0;
    .locals 1

    const-string v0, "kotlinFqName"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/w64;->OooO00o:Ljava/lang/String;

    invoke-static {p0, v0}, Llyiahf/vczjk/w64;->OooO0o0(Llyiahf/vczjk/ic3;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/w64;->OooO0OO:Ljava/lang/String;

    invoke-static {p0, v0}, Llyiahf/vczjk/w64;->OooO0o0(Llyiahf/vczjk/ic3;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_1

    :goto_0
    sget-object p0, Llyiahf/vczjk/w64;->OooO0o0:Llyiahf/vczjk/hy0;

    return-object p0

    :cond_1
    sget-object v0, Llyiahf/vczjk/w64;->OooO0O0:Ljava/lang/String;

    invoke-static {p0, v0}, Llyiahf/vczjk/w64;->OooO0o0(Llyiahf/vczjk/ic3;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_1

    :cond_2
    sget-object v0, Llyiahf/vczjk/w64;->OooO0Oo:Ljava/lang/String;

    invoke-static {p0, v0}, Llyiahf/vczjk/w64;->OooO0o0(Llyiahf/vczjk/ic3;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_3

    :goto_1
    sget-object p0, Llyiahf/vczjk/w64;->OooO0oO:Llyiahf/vczjk/hy0;

    return-object p0

    :cond_3
    sget-object v0, Llyiahf/vczjk/w64;->OooO:Ljava/util/HashMap;

    invoke-virtual {v0, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/hy0;

    return-object p0
.end method

.method public static OooO0o0(Llyiahf/vczjk/ic3;Ljava/lang/String;)Z
    .locals 2

    iget-object p0, p0, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    invoke-virtual {p0, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    const-string p1, "substring(...)"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 p1, 0x30

    invoke-static {p0, p1}, Llyiahf/vczjk/z69;->OooooOo(Ljava/lang/String;C)Z

    move-result p1

    if-nez p1, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/g79;->Oooo0(Ljava/lang/String;)Ljava/lang/Integer;

    move-result-object p0

    if-eqz p0, :cond_1

    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    move-result p0

    const/16 p1, 0x17

    if-lt p0, p1, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    :goto_0
    return v0
.end method
